单点登录服务器：\
在前面实现的Oauth2+JWT的基础上，增加了单点登录的功能
具体修改是：\
1、在AuthorizationServerConfig中修改了redirect_uris到客户端1和客户端2的uri的登录页面中\
2、在AuthorizationServerConfig中添加了configure方法，并且将之前的configure方法中增加了自动认证步骤，使得登录后可以自动授权