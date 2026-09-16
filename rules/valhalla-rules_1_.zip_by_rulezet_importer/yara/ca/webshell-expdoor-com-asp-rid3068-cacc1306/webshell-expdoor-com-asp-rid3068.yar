rule Webshell_Expdoor_com_ASP_RID3068 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file Expdoor.com ASP.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 12:38:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "\">www.Expdoor.com</a>" fullword
      $s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max" 
      $s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
      $s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
      $s16 = "<TITLE>Expdoor.com ASP" fullword
   condition: 
      2 of them
}