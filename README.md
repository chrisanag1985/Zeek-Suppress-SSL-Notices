# Zeek Suppress SSL Notices


This Zeek Module tries to minimize the noise from the `SSL::Invalid_Server_Cert` notices.
If you know that a specific notice is benign but you don't want/cannot load the certificate to Zeek, you can mute it with this module.

## How it works

It loads a list of domains from a file by leveraging the `Input Framework`, so you don't have to stop your Zeek Sensor to make changes to the file and deploy the sensor again.  

When a notice is about to be logged to the `notice.log`, it checks if the domain name string is in the `n$sub` of the notice and if so it will stop the notice from being written in the `notice.log`.

With this module, you can also specify what type of Notice you want to mute. Also, you can specify the direction of the connection.

## Installation

Use the zkg package manager
```
zkg install suppress-ssl-notices
```


## Available Types of Notices

 `Suppress_SSL_Notices::SELF_SIGNED` = "self signed certificate"
 
 `Suppress_SSL_Notices::EXPIRED` = "certificate has expired" 
 
 `Suppress_SSL_Notices::LOCAL_ISSUER` = "unable to get local issuer certificate"
 
 `Suppress_SSL_Notices::SELF_SIGNED_IN_CHAIN` = "self signed certificate in certificate chain"
 
 `Suppress_SSL_Notices::ANY` = "Any of the above"

## Available Types of Network Directions

`Suppress_SSL_Notices::INBOUND` (remote -> local) 

`Suppress_SSL_Notices::OUTBOUND` (local -> remote)

`Suppress_SSL_Notices::INTERNAL` (local -> local)

`Suppress_SSL_Notices::EXTERNAL` (remote -> remote)

`Suppress_SSL_Notices::ANY_DIRECTION`

Note: You have to configure `Site::local_nets` for this to work properly.

## Creating the List

You have to create a file that is accessible to Zeek, and if you have set a Zeek Cluster it must be accessible to `Cluster::MANAGER` only.

The name of the file can be configured by `redef` the `Suppress_SSL_Notices::list_filename` in your `local.zeek`.

Example:
```
redef Suppress_SSL_Notices::list_filename = "/opt/zeek/share/zeek/site/domains.list";
```

### File Format (tab-separated)

Header:
```
#fields domain  notice_msg_type  network_direction  description
```

Example:
```
#fields domain  notice_msg_type  network_direction  description
kaspersky       Suppress_SSL_Notices::ANY       Suppress_SSL_Notices::ANY_DIRECTION     Kaspersky
microsoft.com   Suppress_SSL_Notices::SELF_SIGNED       Suppress_SSL_Notices::INBOUND   Microsoft
```

Note 1: The `description` field must have `UNIQUE` name.

Note 2: In the `domain` you can use the string `ANY_CERT` if you want to catch all the certificates. For example, if you want to catch all the notices for self-signed certificates that correspond to  outgoing traffic you can write something like this:

Example:
```
ANY_CERT Suppress_SSL_Notices::SELF_SIGNED Suppress_SSL_Notices::OUTBOUND  self-signed outgoing
```

More info about how to create a file for Zeek Input Framework: https://docs.zeek.org/en/master/frameworks/input.html#reading-data-into-tables

