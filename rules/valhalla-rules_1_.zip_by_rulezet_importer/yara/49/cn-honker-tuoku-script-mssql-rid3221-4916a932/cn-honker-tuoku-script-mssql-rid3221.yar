rule CN_Honker_Tuoku_script_MSSQL__RID3221 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file MSSQL_.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:52:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "GetLoginCookie = Request.Cookies(Cookie_Login)" fullword ascii
      $s2 = "if ShellPath=\"\" Then ShellPath = \"c:\\\\windows\\\\system32\\\\cmd.exe\"" fullword ascii
      $s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
   condition: 
      filesize < 100KB and all of them
}