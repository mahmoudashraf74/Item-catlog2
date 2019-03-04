from flask import (
    Flask,
    render_template,
    request,
    redirect,
    jsonify,
    url_for,
    flash
)
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__ , template_folder="templates")

CLIENT_ID = json.loads(
    open('/var/www/catalog/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


"""
we want to connect to the database ,
so we will create engine to the database ,
and make session to connect to it

"""
#engine = create_engine('postgresql://catalog:password@localhost/catalog')
engine = create_engine('postgresql://catalog:12345@localhost/catalog')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    """ showLogin:
    The purpose:
     we want the user to take state number ( random generated number )
    to be able to recognize him
    Returns :
    we will pass him to 'login.html' page to be able to login

    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ gconnect( with post method )
    The purpose:
     first : we want to check that the current user
     uses his state token not stolen one
    Returns : error : if not valid access token

    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    """ in next try and except : we make exception for
    flow exchange error : when upgrading a credentials object
    ( of the required third party login provider ), here is Google plus
    Then: we do many checks as obtained up of all functions in the comments
    """
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('/var/www/catalog/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None \
            and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: ' \
              '150px;-webkit-border-radius: 150px;' \
              '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s"
          % login_session['username'])
    print "done!"
    return output


def createUser(login_session):
    """ createUser
    Args : login_session
    we here make a new user with the input data:
    name,email,picture then we add them
    Returns:
    user id
    """
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """ getUserInfo

    Args : User_id
    we here want to retrieve information
    about determined user

    Returns:
    all information about the required user
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """ getUserID

    Args : email
    we here want to retrieve id of the user using his email
    we here have try and except to check for this user
    in our database using his email

    Returns:
    user id if he is exist and none if he isn't exist
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/gdisconnect')
def gdisconnect():
    """gdisconnect
    here : we wnt to disconnect one user,
    Revoke a current user's token and reset their login_session

    """
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?' \
          'token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps
                                 ('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps
                                 ('Failed to revoke token for '
                                  'given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    """ restaurantMenuJSON
    Args :
    restaurant_id

    here we want to retrieve elements in the
    restaurant menu using the id of the restaurant

    Return :
    the elements in the restaurant menu in JSON format

    """
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    """ menuItemJSON
    Args :
    restaurant_id, menu_id

    here we want to retrieve elements in specified menu of
    specified restaurant menu using the id of the restaurant
    and the id of the menu

    Return :
    the elements in the menu of the
    restaurant in JSON format

    """
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    """ restaurantsJSON
    here we want to retrieve all restaurants information

    Return :
    all restaurants information in JSON format

    """
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    """ showRestaurants


    here we want to show the restaurants in our databse
    in ascending order according to
    restaurant name according to check if the user is
    user in our data base or not

    Return :
    if the user is recorded in the database :
    we will redirect him to his restaurant page
    if he isn't :
    we will redirect him to the public restaurant page

    """
    restaurants = session.query(Restaurant).\
        order_by(asc(Restaurant.name))
    if 'username' not in login_session:
        return render_template('publicrestaurants.html',
                               restaurants=restaurants)
    else:
        return render_template('restaurants.html',
                               restaurants=restaurants)


@app.route('/restaurant/new/', methods=['GET', 'POST'])
def newRestaurant():
    """newRestaurant
    Args:
    methods : GET and POST

    here we want to create new restaurant in our database
    we first check for the user , want to create new Restaurant ,
    if he is recorded or not in our database

    if the method == POST :
    we create newRestaurant and add it to the database

    if the method == GET :
    we will return the user to the page to create new restaurant again

    Return:
    the page of the restaurants with the added one
    or the page to create new one if the method == GET

    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newRestaurant = Restaurant(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newRestaurant)
        flash('New Restaurant %s Successfully Created' % newRestaurant.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')


@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    """editRestaurant

    Args:
    the id of the restaurant , we want to modify
    methods : GET and POST
    here we get the required restaurant from
    the database using query with the restaurant_id

    we first check for the user , want to edit his Restaurant ,
    if he is recorded or not in our database

    if the method == POST :
    we edit Restaurant and it modify it in the database

    if the method == GET :
    we will return the user to the page to edit restaurant again

    Return:
    the page of the restaurants with the edited one
    or the page to edit restaurant if the method == GET

    """
    editedRestaurant = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedRestaurant.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized" \
               " to edit this restaurant. Please create your " \
               "own restaurant in order to edit.');}</script>" \
               "<body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedRestaurant.name = request.form['name']
            flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
            return redirect(url_for('showRestaurants'))
    else:
        return render_template('editRestaurant.html',
                               restaurant=editedRestaurant)


@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    """deleteRestaurant

    Args:
    the id of the restaurant , we want to delete
    methods : GET and POST
    here we get the required restaurant from
    the database using query with the restaurant_id

    we first check for the user , want to edit his Restaurant ,
    if he is recorded or not in our database

    if the method == POST :
    we delete Restaurant and delete it from the database

    if the method == GET :
    we will return the user to the page to delete restaurant again

    Return:
    the page of the restaurants without the deleted one
    or the page to edit restaurant if the method == GET

    """
    restaurantToDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if restaurantToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You aren't authorized " \
               "to delete this restaurant,Please create your own restaurant" \
               " in order to delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(restaurantToDelete)
        flash('%s Successfully Deleted' % restaurantToDelete.name)
        session.commit()
        return redirect(url_for('showRestaurants',
                                restaurant_id=restaurant_id))
    else:
        return render_template('deleteRestaurant.html',
                               restaurant=restaurantToDelete)


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    """ showMenu

    Args :
    restaurant_id

    here we want to show the menu of the restaurant
    in our database according to check if the user
    is user in our data base or not

    Return :
    if the user is recorded in the database :
    we will redirect him to his restaurant menu page
    if he isn't :
    we will redirect him to the public restaurant menu

    """
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    creator = getUserInfo(restaurant.user_id)
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return render_template('publicmenu.html', items=items,
                               restaurant=restaurant, creator=creator)
    else:
        return render_template('menu.html', items=items,
                               restaurant=restaurant, creator=creator)


@app.route('/restaurant/<int:restaurant_id>/menu/new/',
           methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    """newMenuItem
    Args:
    restaurant_id
    and : methods : GET and POST

    here we want to create new restaurant in our database
    we first check for the user , want to create new Restaurant ,
    if he is recorded or not in our database

    if the method == POST :
    we create new menu item and add it to the restaurant in the database

    if the method == GET :
    we will return the user to the page to create new menu item again

    Return:
    the page of the restaurant with the added menu item
    or the page to create new item one if the method
    == GET

    """
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).\
        filter_by(id=restaurant_id).one()
    if login_session['user_id'] != restaurant.user_id:
        return "<script>function myFunction() {alert('You are not " \
               "authorized to add menu items to this restaurant." \
               " Please create your own restaurant in " \
               "order to add items.');}" \
               "</script><body onload='myFunction()'>"
    if request.method == 'POST':
            newItem = MenuItem(name=request.form['name'],
                               description=request.form['description'],
                               price=request.form[
                               'price'], course=request.form['course'],
                               restaurant_id=restaurant_id,
                               user_id=restaurant.user_id)
            session.add(newItem)
            session.commit()
            flash('New Menu %s Item Successfully Created' % (newItem.name))
            return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant=restaurant,
                               restaurant_id=restaurant_id)


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit',
           methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    """editMenuItem

    Args:
    the id of the restaurant , the id of the menu
    we want to edit
    methods : GET and POST
    here we get the required menu of the required restaurant from
    the database using query with the menu_id and restaurant_id

    we first check for the user , want to edit his menu item ,
    if he is recorded or not in our database

    if the method == POST :
    we edit menu item in the Restaurant and it modify it in the database

    if the method == GET :
    we will return the user to the page to edit menu item again

    Return:
    the page of the restaurants with the edited one
    or the page to edit menu item of the restaurant if
    the method == GET

    """
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    restaurant = session.query(Restaurant).\
        filter_by(id=restaurant_id).one()
    if login_session['user_id'] != restaurant.user_id:
        return "<script>function myFunction() " \
                "{alert('You are not authorized "\
                "to edit menu items to this restaurant.Please create your own"\
                "restaurant in order to edit items.');}</script>"\
                "<body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu',
                                restaurant_id=restaurant_id))
    else:
        return render_template(
            'editmenuitem.html', restaurant_id=restaurant_id,
            menu_id=menu_id, item=editedItem)


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    """deleteMenuItem

    Args:
    the id of menu item , we want to delete, the id of the restaurant
    methods : GET and POST
    here we get the required menu item and restaurant from
    the database using query with the menu_id and restaurant_id

    we first check for the user , want to delete his menu item
    from the restaurant ,
    if he is recorded or not in our database

    if the method == POST :
    we delete menu item from the Restaurant and delete it from the database

    if the method == GET :
    we will return the user to the page to delete menu item again

    Return:
    the page of the restaurants without the deleted one
    or the page to edit restaurant if the method == GET

    """
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).\
        filter_by(id=restaurant_id).one()
    itemToDelete = session.query(MenuItem).\
        filter_by(id=menu_id).one()
    if login_session['user_id'] != restaurant.user_id:
        return "<script>function myFunction() {alert(" \
               "'You are not authorized to"\
               "delete menu items to this restaurant." \
               " Please create your own restaurant in order "\
               "to delete items.');}" \
               "</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu',
                                restaurant_id=restaurant_id))
    else:
        return render_template('deleteMenuItem.html',
                               restaurant=restaurant,
                               item=itemToDelete)


@app.route('/disconnect')
def disconnect():
    """ diconnect:
    here we want to log out from the website:
    we first check if he is logged in or not
    if he is logged in :
    log out and delete his session information
    Returns:
    if he isn't logged in :
    redirect the user to show Restaurants page

    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showRestaurants'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showRestaurants'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
