rule MAL_Xbash_JS_Sep18_RID2D2C : DEMO MAL T1059_007 {
   meta:
      description = "Detects XBash malware"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
      date = "2018-09-18 10:20:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "f888dda9ca1876eba12ffb55a7a993bd1f5a622a30045a675da4955ede3e4cb8"
      tags = "DEMO, MAL, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "var path=WSHShell" fullword ascii
      $s2 = "var myObject= new ActiveXObject(" ascii
      $s3 = "window.resizeTo(0,0)" fullword ascii
      $s4 = "<script language=\"JScript\">" fullword ascii
   condition: 
      filesize < 5KB and 3 of them
}