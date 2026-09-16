rule CN_Honker_Webshell__Serv_U_by_Goldsun_asp3_Serv_U_asp_RID3BB0 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - from files Serv-U_by_Goldsun.asp, asp3.txt, Serv-U asp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 20:39:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "87c5a76989bf08da5562e0b75c196dcb3087a27b"
      hash2 = "cee91cd462a459d31a95ac08fe80c70d2f9c1611"
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "c.send loginuser & loginpass & mt & deldomain & quit" fullword ascii
      $s2 = "loginpass = \"Pass \" & pass & vbCrLf" fullword ascii
      $s3 = "b.send \"User go\" & vbCrLf & \"pass od\" & vbCrLf & \"site exec \" & cmd & vbCr" ascii
   condition: 
      filesize < 444KB and all of them
}