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