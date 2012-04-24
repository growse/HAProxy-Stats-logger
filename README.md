#HAProxy Stats Logger

I wrote this small script to solve the problem of storing HAProxy requests in a database. It listens on a syslog port (5140 by default), parses HAProxy requests out and stores them in a database of your choice. It currently runs in the foreground, so use of something like supervisord is recommended.

TODO:

* Better configurable database options
* SSL requests support
* include DB schema file
