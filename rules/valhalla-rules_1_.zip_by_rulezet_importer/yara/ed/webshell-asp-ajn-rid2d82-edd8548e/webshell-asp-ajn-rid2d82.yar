rule Webshell_asp_ajn_RID2D82 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ajn.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword
      $s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve" 
   condition: 
      all of them
}