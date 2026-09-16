rule Webshell_elmaliseker_2_RID2FC5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file elmaliseker.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:11:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx" 
      $s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but" 
   condition: 
      all of them
}