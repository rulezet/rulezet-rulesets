rule Webshell_HYTop_DevPack_2005Red_RID31B8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005Red.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 13:34:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "scrollbar-darkshadow-color:#FF9DBB;" 
      $s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace" 
      $s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)" 
   condition: 
      all of them
}