rule CN_disclosed_20180208_lsls_RID2FCC : CHINA DEMO FILE MAL {
   meta:
      description = "Detects malware from disclosed CN malware set"
      author = "Florian Roth"
      reference = "https://twitter.com/cyberintproject/status/961714165550342146"
      date = "2018-02-08 12:12:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "94c6a92984df9ed255f4c644261b01c4e255acbe32ddfd0debe38b558f29a6c9"
      tags = "CHINA, DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 3000KB and $x1
}