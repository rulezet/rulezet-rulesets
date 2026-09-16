rule CN_Honker_Webshell_ASP_asp4_RID3117 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp4.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:07:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
      $s6 = "Response.Cookies(Cookie_Login) = sPwd" fullword ascii
      $s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
   condition: 
      filesize < 150KB and all of them
}