rule CN_Honker_Webshell_Interception3389_get_RID35C6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file get.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:27:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "userip = Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\")" fullword ascii
      $s1 = "file.writeline  szTime + \" HostName:\" + szhostname + \" IP:\" + userip+\":\"+n" ascii
      $s3 = "set file=fs.OpenTextFile(server.MapPath(\"WinlogonHack.txt\"),8,True)" fullword ascii
   condition: 
      filesize < 3KB and all of them
}