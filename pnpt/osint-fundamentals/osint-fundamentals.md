# OSINT Fundamentals

## Introduction

OSINT is the process of gathering information from external resources.

## What is OSINT?

Intelligence lifecycle:
- Planning and Direction
- Collection
- Processing and Exploitation
- Analysis and Production
- Dissemination and Integration

## Sock Puppets

An online identity that is a misrepresentation of you when researching OSINT.

URLs:
- https://web.archive.org/web/20210125191016/https://jakecreps.com/2018/11/02/sock-puppets/
- https://www.secjuice.com/the-art-of-the-sock-osint-humint/
- https://www.reddit.com/r/OSINT/comments/dp70jr/my_process_for_setting_up_anonymous_sockpuppet/
- https://www.fakenamegenerator.com/
- https://www.thispersondoesnotexist.com/

## Search Engine OSINT

Google, DuckDuckGo, Bing, Yandex

Google Advanced Search

Use words like:
- `password`, `pass`, `pwd`

Can specify site:
- `site:reddit.com`

Combine words:
- `"Linear Algebra"`

Can force for both words to appear:
- `uu AND "Linear Algebra"`

Can also use `OR`:
- `uu OR "Linear Algebra"`

Can use wildcard:
- `* Kiezebrink`

Can search for specific filetypes:
- `filetype:pdf`
- `filestype:xlsx`
- `filestype:docx`

Can use `-` to remove a subdomain:
- `-www`, `-forums`

Search for something in text:
- `intext:password`

Look for something in title:
- `intitle:password`

## Image OSINT

We can reverse image search:
- `lens.google.com` (Google images)
  - Find image source
  - Change the area on the image that is reverse image searched (Works well for buildings)
- `tineye.com`
- `pimeyes.com` (Paid)

Viewing EXIF data:
- Data on where a photo is taken can be found inside the image's metadata.
- `jimpl.com`

Physical Location OSINT:
- Look the location up on `google maps`.
- Use the satellite view.
  - You can try to find other satellite images
- Is there private access?
- Is there a smoke area?
- Look for the location of doors

Identifying Geographical Locations
- Street signs
- Cars
- Weather
- Buildings
- etc.
- *Play GeoGuessr to practice!*
  - https://somerandomstuff1.wordpress.com/2019/02/08/geoguessr-the-top-tips-tricks-and-techniques/

## E-mail OSINT

Common tools:
- `hunter.io`
  - Type in a company name
  - Can analyze e-mail address patterns
- `Phonebook.cz`
  - Look up domain
  - Can find Domains, E-mail addresses and URLs
- `voilanorbert.com`
- `clearbit` extension (Only in chrome)

Verify e-mail addresses:
- `tools.verifyemailaddress.io` (emailhippo)
- `email-checker.net/validate`
- Try to log in to the account and click forgot password.

## Password OSINT

Look at repeat offenders!

Try to tie accounts to each other.

Websites:
- `dehashed.com` (Paid)
- `hashes.org`
  - Search for found hashes
- `weleakinfo.to` (Paid)
- `leakcheck.io` (Paid)
- `snusbase.com` (Paid)
- `haveibeenpwned.com`
- `scylla.sh`
  - `email:test@test.com`
  - `domain:test.com`
  - `password:12345`

## Username OSINT

Websites:
- `namechk.com`
  - Finds usernames that are available
- `whatsmyname.app`
  - Find accounts with a username
- `namecheckup.com`
- Go to social media to enumerate usernames
  - `socialmedia.com/[username]`
- Slowly type in usernames in social media applications

## Searching for people

Websites:
- `whitepages.com`
- `truepeoplesearch.com`
- `fastpeoplesearch.com`
- `fastbackgroundcheck.com`
- `webmii.com`
- `peekyou.com`
- `411.com`
- `spokeo.com`
- `thatsthem.com`
- *Use Google!*

Use voter records.
- `voterrecords.com`

Hunting phone numbers
- `truecaller.com` (Have to log in)
- `calleridtest.com`
- `infobel.com`

Discovering birthdates
- Include **birthday** or **happy birthday** in searches

Searching for resumes
- `site:linkedin.com`

## Social Media OSINT

### Twitter/X OSINT

https://github.com/rmdir-rp/OSINT-twitter-tools

Search:
- `from:[user]`
- `to:[user]`
- `@[user]`
- `since:[yyyy-mm-dd]`
- `until:[yyyy-mm-dd]`
- `geocode:[x,y,{range}]`
  - Get coordinates from Google maps
- *Combine these!*

### Facebook OSINT

Websites:
- https://sowsearch.info
- https://intelx.io/tools?tab=facebook

Get an ID for an account:
- Right click -> View page source -> `userID`

### Instagram OSINT

Look at who people are following

Look for names

Look for tags

Research images

Get profile ID:
- Right click -> View page source -> `profilePage_` or `profile_id`

Use https://imginn.com/ to download images from a profile

### Snapchat OSINT

Search usernames and try slow typing

Go to https://map.snapchat.com

### Reddit OSINT

Can use quotes for specific sentences.

Search google with `site:reddit.com`

Look at comments and posts

### LinkedIn OSINT

Check for contact info

Works best if you have many connections

### TikTok OSINT

Look at videos and do image OSINT

Do image OSINT on profile pictures

## Website OSINT

**Do not underestimate Google!**

Websites:
- `builtwith.com`
  - Tells you what technology the website is built with
- `centralops.net`
  - Do a `whois`
  - Can get you an IP-address
  - Can disclose names, addresses, phone numbers, etc.
  - Also checks the services
  - Discloses some subdomains and headers
- `dnslytics.com`
  - Reverse lookup IP-addresses
  - Can find all websites hosted from this IP-address
- `spyonweb.com`
  - Reverse lookup
  - Allows for URLs
  - Has analytics
  - Has lookup for `UA-`
- `virustotal.com`
  - File search
  - URL search
  - Get the `UA-`
  - Gives headers
- Look at reddit: `reddit.com/domain/[URL]/`
- `visualping.io`
  - Pings you for website changes
- `backlinkwatch.com`
  - Looks at places where the website is posted
- `viewdns.info`
- `urlscan.io`
- `dnsdumpster.com` 
  - Does some domain mapping!
- `web-check.as93.net`

Finding subdomains:
- `crt.sh`
  - Wildcard: %
  - Example: `%.test.com`
- Google
  - Wildcard: *
  - Example: `*.test.com`
  - Use `-[subdomain]` to remove unwanted subdomains

Additional great resources:
- `shodan.io`
  - Search an IP-address
  - Find vulnerable services
  - Searching
    - `city:[city]`
    - `port:3389`
    - `org:[organisation]`
  - Also gives images
- `archive.org`
  - Gives snapshots of a website at different times.
- Google
  - Can look at cached version of website (Little arrow behind URL)
  
## Business OSINT

Start on LinkedIn

Websites:
- `opencorporates.com`
  - Addresses
  - Who are high ranking employees
  - Annual report
  - More articles
- `sosnc.com`
- `aihitdata.com`
- `indeed.com`
  - Can find software in job postings

## Wireless OSINT

https://wigle.net/

## OSINT Tools

### Image & Location OSINT

Use `exiftool`
- `exiftool [file]`

### Hunting E-mails and Breached Data

https://github.com/hmaverickadams/DeHashed-API-Tool (Requires paid access to DeHashed)

### Username & Account OSINT

Use `sherlock`
- `sherlock [username]`

### Phone Number OSINT

Use `phoneinfoga` from github
- `phoneinfoga scan -n [phone number]`
- `phoneinfoga serve -p [port]`
  - Serves a website on localhost to look up phone numbers

### Social Media OSINT

`InstagramOSINT` on GitHub

### Exploring OSINT Frameworks

Frameworks
- `recon-ng`
  - `marketplace search`
  - `marketplace install hackertarget`
    - `modules load hackertarget`
    - `options set SOURCE [domain]`
    - `run`
    - `show hosts`
  - `marketplace install profiler`
    - `modules load profiler`
    - `options set SOURCE [username]`
    - `run`
    - `show profiles`
- `maltego`
- `Spiderfoot`
- `sn0int`

### Hunchly

website: https://hunch.ly

A web-capture tool for investigations. 

### Website OSINT tools

Tools:
- `whois [url]`
- `subfinder` https://github.com/projectdiscovery/subfinder
  - `sudo apt install subfinder`
  - `subfinder -d [url]`
- `assetfinder` https://github.com/tomnomnom/assetfinder
  - `assetfinder [url]`
  - Look for `adm`, `vpn`, `dev`, `api`, etc...
- `amass` https://github.com/OWASP/Amass
  - `amass enum -d [url]`
- `httprobe` https://github.com/tomnomnom/httprobe
  - `cat [url].txt | httprobe -s -p https:443`
- `gowitness` https://github.com/sensepost/gowitness/wiki/Installation
  - `gowitness file -f [file].txt -P [image folder] --no-http`