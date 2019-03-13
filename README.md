# About

LM is a dedicated authentication service for P10-based IRC daemons.
It is intended to be used alongside
[lightweight (L)](https://github.com/quakenet/lightweight), providing the
authentication information L requires.

It uses [Monocypher](https://github.com/LoupVaillant/Monocypher) for all
cryptographic operations.
This means it uses argon2i for password hashing in particular.

# Installation

To use LM, you will need to install lightweight (L) first.

Before installing LM itself, you will need to install a C compiler and the
dependencies for LM.
The following command is an example listing for Debian-based Linux
distributions.

    # apt-get install build-essential libevent-dev

Then, get LM and compile it.

    $ git clone https://github.com/fscoto/lm.git
    $ cd lm
    $ make

Copy the configuration file and edit it as required.

    $ cp lm.example.ini lm.ini
    $ $EDITOR lm.ini

Now edit `ircd.conf` and add the required linking block.
For example:

    Connect {
      name = "lm.services.invalid";
      host = "127.0.0.1";
      password = "l1nkm3upsc0tty";
      port = 4400;
      class = "Server";
      autoconnect = no;
    };

Finally, start LM.

    $ ./lm

## Creating your account

Create your account so that L can recognize you.
Replace `LM` with the nick you configured, `lm.services.invalid` with the
server name you configured, `nick` with the account name you created with L
previously and `email` with your e-mail address.
You will receive a confirmation e-mail address unless you disabled e-mail in
`lm.ini`.

    /msg LM@lm.services.invalid HELLO nick email email

You should now be able to join a channel and register it with L through LM.

    /join #twilightzone
    /msg LM chanregister #twilightzone

L and LM should work as expected.

# Other Notes

* It's called LM as a homage of the broken
  [LM hash](https://en.wikipedia.org/wiki/LAN_Manager#LM_hash_details), which is
  both short, memorable, related to authentication and starts with L.
  However, LM uses the argon2i algorithm for password hashing.
* Stock ircu should work. L does not seem to be doing anything beyond what is
  part of ircu already; LM has been tested on stock ircu in particular.
* IRC operators can use the `LOSTPASS` command without providing an e-mail
  address. If sending e-mail is disabled, IRC operators can silently reset any
  user's password at their discretion.
* **The database schema and configuration file can and will change arbitrarily**
  until an actual release has been made.
  Please reach out to me if you want to use LM on a live network so I know that
  special care must be taken from there on out.

# License

ISC, see LICENSE

# Bugs and Security Issues

* [ircu does not support TLS](https://sourceforge.net/p/undernet-ircu/feature-requests/33/).
  Passwords can be trivially intercepted by any attacker that can sniff network
  traffic (which is a lot of people on public wi-fi hotspots).
  It's not really possible to tack on something more reasonable for
  authentication.
  Forks of ircu exist that do support TLS, such as
  [nefarious2](https://github.com/evilnet/nefarious2).
  LM (and L) both only use very basic ircu server-side facilities,
  so that you should be able to use any ircu fork in theory.

Loads more, probably.

**This is not production software.
It has not spent even a single second of its life in a live environment.
Most likely, this program is not secure.**

