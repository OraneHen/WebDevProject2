/* Add your Application JavaScript */
Vue.component('app-header', {
    template: `
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
      <a class="navbar-brand" to="#">
      <img src="static/extras/photogram.png" width="35" height="35" class="d-inline-block align-top" alt=""><em>Photogram</a>
      
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarSupportedContent">
        <ul class="nav navbar-nav navbar-right">
          <li class="nav-item active">
            <router-link class="nav-link" to="/">Home <span class="sr-only">(current)</span></router-link>
          </li>
          <li class="nav-item active">
            <router-link class="nav-link" to="/explore">Explore<span class="sr-only">(current)</span></router-link>
          </li>
           <li class="nav-item active ">
            <router-link class="nav-link" to="/users/0">My Profile<span class="sr-only">(current)</span></router-link>
          </li>
          <li class="nav-item active nav navbar-right">
            <router-link class="nav-link" to="/logout">Logout<span class="sr-only">(current)</span></router-link>
          </li>
        </ul>
      </div>
    </nav>
    `,watch: {
        '$route' (to, fom){
            this.reload()
        }
      },
    created: function() {
        let self = this;
        self.user=localStorage.getItem('token');
        self.userid=localStorage.getItem('userid');
        self.userphoto=localStorage.getItem('userphoto');
    },
    data: function() {
        return {
            user: [],
            userid:'',
            userphoto:'',
        }
    },
    methods:{
        reload(){
            let self = this;
            self.user= localStorage.getItem('token');
            self.userid=localStorage.getItem('userid');
            self.userphoto=localStorage.getItem('userphoto');
        }
    }
});

Vue.component('app-footer', {
    template: `
    <footer>
        <div class="container">
            <p>Copyright &copy; Photogram Inc.</p>
        </div>
    </footer>
    `
});

const Home = Vue.component('home', {
   template: `
   <div class="row justify-content-center" id = "mhm" >
    <div class="col-4">
        <img src="static/extras/left grid image.png" width="350" height="300" alt = 'Placeholder' ></img>
    </div> 
    <div class="col-4">
          <div v-if="usertoken=='Not logged in'">
           <a class="navbar-brand nav-justified" to="#">
           <img src="static/extras/photogram.png" width="35" height="35" class="d-inline-block align-top" alt="">Photogram</a>
           <hr>
           <p>Share exciting photos of you with your friends and family.</p>
           <div></div>
          <router-link class="btn btn-success col-md-4" to="/register">Register</router-link>
          <router-link class="btn btn-primary col-md-4" to="/login">Login</router-link>
    </div>
    </div>
  </div>
    
    <div v-else>
        <h3>You are already logged in </h3>
    </div>
   `,
    created: function(){
        let self = this;
        if (localStorage.getItem('token')!==null){
            usertoken=localStorage.getItem('token');
        }
    },
    data: function() {
       return {
           usertoken:'Not logged in'
       }
    }
});

const Register=Vue.component('register',{
    template:`<div>
    <li v-for="responses in response" class="list alert alert-success">
            {{ responses.message }}
    </li>
    <ul class="list">
        <li v-for="message in error"class="list alert alert-danger">
            {{message}}
        </li>
    </ul>
    <form id="registerform" @submit.prevent="register" method="POST" enctype="multipart/form-data">
        <div class="form-group">
            <label for="usern">Username</label>
            <input type="text" class="form-control" id="usern" name="username" placeholder="Enter a username">
        </div>
        <div class="form-group">
            <label for="passw">Password</label>
            <input type="password" class="form-control" id="passw" name="password" placeholder="Enter Password">
        </div>
        <div class="form-group">
            <label for="fname">Firstname</label>
            <input type="text" class="form-control" id="fname" name="firstname" placeholder="Enter Firstname">
        </div>
        <div class="form-group">
            <label for="lname">Lastname</label>
            <input type="text" class="form-control" id="lname" name="lastname" placeholder="Enter Lastname">
        </div>
        <div class="form-group">
            <label for="mail">E-mail</label>
            <input type="email" class="form-control" id="mail" name="email" placeholder="eg. jdoe@example.com">
        </div>
        <div class="form-group">
            <label for="locat">Location</label>
            <input type="text" class="form-control" id="locat" name="location" placeholder="eg. Kingston">
        </div>
        <div class="form-group">
            <label for="biog">Biography</label>
            <textarea class="form-control" id="biog" name="bio"></textarea>
        </div>
        <div class="form-group">
            <label for="photo">Profile Photo</label>
            <div class="upload-btn-wrapper">
                <input type="file" name="photo" />
            </div>
        </div>
        <button class="btn btn-success" type="submit">Register</button>
    </form>    
    </div>`
, data: function(){
    return {
        response:[],
        error:[]
    }
},methods:{
    register: function(){
        let self = this;
        let registerform = document.getElementById('registerform');
        let form_data = new FormData(registerform);
        fetch("/api/users/register", { 
            method: 'POST', 
            body: form_data,
            headers: {
                    'X-CSRFToken': token
                },
            credentials: 'same-origin'
            })
            .then(function (response) {
                return response.json();
            })
            .then(function (jsonResponse) {
                if(jsonResponse.response){
                    alert("Account created Please login.")
                    self.$router.push('/login');
                } 
                else{     
                    self.error=jsonResponse.errors["0"]["error"];  
                }
            
            })
            .catch(function (error) {
                console.log(error);
            });
    }
}
});

const Login =Vue.component('login',{
    template:`<div>
    <li v-for="error in error"class="list alert alert-danger">
        {{error}}
    </li>
    <form id="loginform" method="POST" @submit.prevent="login">
        <div class="form-group">
            <label for="usern">Username</label>
            <input type="text" class="form-control" id="usern" name="username">
        </div>
        <div class="form-group">
            <label for="passw">Password</label>
            <input type="password" class="form-control" id="passw" name="password">
        </div>
    <button class="btn btn-success" type="submit">Login</button>
    </form>    
    </div>`
, data: function() {
    return {
        response:[],
        error:[]
    }
    
}, methods:{
    login: function(){
        let self = this;
        let loginform = document.getElementById('loginform');
        let form_data = new FormData(loginform);
        fetch("/api/auth/login", { 
            method: 'POST', 
            body: form_data,
            headers: {
                    'X-CSRFToken': token
                },
            credentials: 'same-origin'
            })
            .then(function (response) {
                return response.json();
            })
            .then(function (jsonResponse) {
                if(jsonResponse.errors){
                    self.error = jsonResponse.errors['0']['error'];
                }
                else{
                    let jwt_token = jsonResponse.response["0"].token;
                    let userid=jsonResponse.response["0"].userid;
                    let userphoto=jsonResponse.response["0"].userphoto;
                    localStorage.setItem('token', jwt_token);
                    localStorage.setItem('userid',userid);
                    localStorage.setItem('userphoto',userphoto);
                    alert(jsonResponse.response["0"].message);
                    self.$router.push({path:`/explore`})
                }
                
            })
            .catch(function (error) {
                console.log(error);
            });
    }
}
    
});

const Logout=Vue.component('logout',{
    template:`<div v-if="usertoken !=''">
    <p>Are you sure you want to logout</p>
    <form id="logout" @submit.prevent="logout">
    <button class="btn btn-primary" type="submit" >Logout</button>
    </form>
    </div>
    <div v-else><h3>You are not logged in</h3></div>
    `,created:function(){
            let self = this;
            if(localStorage.getItem('token')!==null){
                self.usertoken=localStorage.getItem('token');   
            }
        },
    data:function(){
        return {
            response:[],
            usertoken:''
        }
    },methods:{
        logout: function(){
        if (localStorage.getItem('token')!==null){
            let self = this;
            self.usertoken=localStorage.getItem('token');
            let logoutform = document.getElementById('logout');
            let form_data = new FormData(logoutform);
            fetch("/api/auth/logout", { 
                method: 'GET',
                headers: {
                        'Authorization': 'Bearer ' + localStorage.getItem('token'),
                        'X-CSRFToken': token
                    },
                credentials: 'same-origin'
                
                })
                .then(function (response) {
                    return response.json();
                })
                .then(function (jsonResponse) {
                    if(jsonResponse.response){
                        localStorage.removeItem('token');
                        localStorage.removeItem('userid');
                        localStorage.removeItem('userphoto');
                        alert(jsonResponse.response["0"].message);
                         self.$router.push('/')
                    }
                })
                .catch(function (error) {
                    console.log(error);
                });
            }
        }    
    }
})

const AddPost=Vue.component('addpost',{
    template:`
    <div v-if="usertoken !== ''">
        <div class=upload>
            <h1>Upload</h1>
            <ul class="list">
                <li v-for="error in error"class="list">
                    {{error}}
                </li>
            </ul>
            <form id="postform"  @submit.prevent="uploadPost" method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="photo">Photo</label>
                    <div class="upload-btn-wrapper">
                        <input type="file" name="photo" />
                    </div>
                </div>
                <div class="form-group">
                    <label for="cap">Caption</label>
                    <textarea class="form-control" id="cap" name="caption"></textarea>
                </div>
                <button class="btn btn-primary" type="submit">Upload</button>
            </form>
        </div>
    </div>
    <div v-else>
        <h5>You are not logged in</h5>
    </div> `,
        created:function(){
            let self = this;
            if(localStorage.getItem('token')!==null){
                self.usertoken=localStorage.getItem('token');   
            }
        },
    data:function(){
        return {
            response:[],
            error:[],
            usertoken:''
        }
    },methods: {
        uploadPost: function () {
            let self = this;
            let uploadForm = document.getElementById('postform');
            let form_data = new FormData(uploadForm);
            fetch("/api/users/0/posts", { 
            method: 'POST',
            body: form_data,
            headers: {
                    'Authorization': 'Bearer ' + localStorage.getItem('token'),
                    'X-CSRFToken': token
                },
            credentials: 'same-origin'
            
            })
            .then(function (response) {
                return response.json();
            })
            .then(function (jsonResponse) {
                 if(jsonResponse.response){
                    alert(jsonResponse.response["0"].message);
                    self.$router.push({path:`/users/${0}`})
                } 
                else{     
                    self.error=jsonResponse.errors["0"]["error"];  
                }
            })
            .catch(function (error) {
                console.log(error);
            });
        }
    }
    
});

const Explorer=Vue.component('Allposts',{
template:`
            <div v-if="usertoken !=''">
                <div style="margin-top: 20%;">
                    <router-link class="btn btn-success col-md-5" to="/postnew">New Post</router-link>
                </div>
                <div v-if="posts.length>=1">
                    <div v-for="post in posts">
                        <img style="width:100px; height:100px" v-bind:src="post.userphoto"><h4>{{post.username}}</h4>
                        <img style="width:600px; height:600px" v-bind:src="post.photo"/>
                        <p>{{post.caption}}</p>
                        <div>
                            <div v-if="post.likebyuser=='No'">
                                <button :id=post.id v-on:click="like(post.id)" style="background-color:transparent">
                                    <img style="width:35px; height:35px" v-bind:src="'static/extras/wave.jpg'" />
                                </button>
                            </div>
                            <div v-else>
                                <button style="background-color:transparent" disabled>
                                    <img style="width:35px; height:35px" v-bind:src="'static/extras/wave.png'" />
                                </button>
                            </div>
                        <p>Likes: <span :id="'like'+post.id">{{post.likes}}</span></p></div>
                        <p>{{post.created_on}}</p>
                    </div>
                </div>
                <div v-else>
                    <h5> No Posts</h5>
                </div>
        </div>
        <div v-else>
            <h3>You are not Logged in</h3>
        </div>`,
        created: function () {
            let self = this;
            if(localStorage.getItem('token')!==null){
                self.usertoken=localStorage.getItem('token');
                console.log(self.usertoken);
                fetch("/api/posts", { 
                method: 'GET',
                headers: {
                        'Authorization': 'Bearer ' + localStorage.getItem('token'),
                        'X-CSRFToken': token
                    },
                credentials: 'same-origin'
                
                })
                .then(function (response) {
                    return response.json();
                })
                .then(function (jsonResponse) {
        
                    self.posts=jsonResponse.response['0']['posts'];
                    console.log(self.posts);
                })
                .catch(function (error) {
                    console.log(error);
                });
            }
        },
        data:function(){
            return {
                response:[],
                posts:[],
                error:[],
                usertoken:''
            }
        },
        methods:{
            like:function(postid){
                let self= this;
                let likevalue=document.getElementById('like'+postid).innerHTML;
                likevalue=parseInt(likevalue)+1;
                fetch("/api/posts/"+postid+"/like", { 
                    method: 'POST',
                    headers: {
                            'Authorization': 'Bearer ' + localStorage.getItem('token'),
                            'X-CSRFToken': token
                        },
                    credentials: 'same-origin'
                    
                    })
                    .then(function (response) {
                        return response.json();
                    })
                    .then(function (jsonResponse) {
                        if (jsonResponse.response){
                            alert(jsonResponse.response['0']['message']);
                            document.getElementById('like'+postid).innerHTML=likevalue;
                            document.getElementById(postid).disabled=true;
                        }
                    })
                    .catch(function (error) {
                        console.log(error);
                    });
            }
                
        }
})

const UserPost=Vue.component('Userposts',{
template:`<div v-if="usertoken!==''">
                <div v-if="error ===''">
                    <div>
                        <img style="width:100; height:100px;" v-bind:src="userinfo.photo" />
                        <p>{{userinfo.fname}}<span> {{userinfo.lname}}</span></p>
                        <p>{{userinfo.location}}</p>
                        <p>{{userinfo.joined}}</p>
                        <p>{{userinfo.bio}}</p>
                    </div>
                    <div>
                        <p>{{numposts}} </br> Posts</p>
                        <p><span id='followers'>{{follows}}</span> </br>Following</p>
                        <div v-if="toshow=='Yes'">
                            <form method="POST" @submit.prevent="follow">
                                <input  id='userid' type="hidden" :value=userinfo.id >
                                <button id='follow'>Follow</button>
                            </form>
                        </div>
                        <div v-if="isfollowing !==''">
                            <p>{{isfollowing}}</p>
                        </div>
                    </div>
                    <div v-if="posts.length > 0">
                        <div v-for="photo in posts">
                            <img v-bind:src="photo.photo"/>
                        </div>
                    </div>
                    <div v-else><h3>No posts yet</h3></div>
                </div>
                <div v-else><h1>User Doesn't exist</h1></div>
            </div>
            <div v-else>
                <h3>You are not logged in</h3>
            </div>`,
        created: function () {
            if(localStorage.getItem('token')!==null){
                let self = this;
                self.usertoken=localStorage.getItem('token');
                fetch("/api/users/"+this.$route.params.user_id+"/posts", { 
                method: 'GET',
                headers: {
                        'Authorization': 'Bearer ' + localStorage.getItem('token'),
                        'X-CSRFToken': token
                    },
                credentials: 'same-origin'
                
                })
                .then(function (response) {
                    return response.json();
                })
                .then(function (jsonResponse) {
                    if (jsonResponse.response){
                        self.posts=jsonResponse.response['0']['posts']['0'];
                        self.numposts=jsonResponse.response['0']['numposts'];
                        self.follows=jsonResponse.response['0']['follows'];
                        self.userinfo=jsonResponse.response['0']['userinfo'];
                        console.log(self.userinfo);
                        if((jsonResponse.response['0']['current']==='No' &&  jsonResponse.response['0']['following']==='No')===true){
                            self.toshow='Yes';
                        }
                        if(jsonResponse.response['0']['current']==='No' && jsonResponse.response['0']['following']==='Yes'){
                                self.isfollowing='You are already following '+self.userinfo['username'];
                        }
                    }
                    else{
                        self.error=jsonResponse.error['error'];
                    }
                })
                .catch(function (error) {
                    console.log(error);
                });
            }
            
        },
        data:function(){
            return {
                usertoken:'',
                posts:[],
                follows:0,
                numposts:0,
                userinfo:[],
                isfollowing:'',
                error:'',
                toshow:'',
            }
        },methods:{
            follow:function(){
                let self= this;
                let followid=document.getElementById('userid').value;
                let updatefollows=document.getElementById('followers').innerHTML;
                updatefollows=parseInt(updatefollows)+1;
                fetch("/api/users/"+followid+"/follow", { 
                    method: 'POST',
                    headers: {
                            'Authorization': 'Bearer ' + localStorage.getItem('token'),
                            'X-CSRFToken': token
                        },
                    credentials: 'same-origin'
                    
                    })
                    .then(function (response) {
                        return response.json();
                    })
                    .then(function (jsonResponse) {
                        if (jsonResponse.response){
                            alert(jsonResponse.response['message']);
                            document.getElementById('followers').innerHTML=updatefollows;
                            document.getElementById('follow').disabled=true;
                        }
                    })
                    .catch(function (error) {
                        console.log(error);
                    });
            }
                
        }
})
// Define Routes
const router = new VueRouter({
    routes: [
        { path: "/", component: Home },
        { path:"/login",component: Login },
        { path:"/postnew", component:AddPost},
        { path:"/register", component:Register},
        { path:"/logout",component:Logout},
        { path:"/explore",component:Explorer},
        { path:"/users/:user_id",component:UserPost}
    ]
});

// Instantiate our main Vue Instance
let app = new Vue({
    el: "#app",
    router
});