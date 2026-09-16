rule VBScript_Favicon_File_RID2F22 : ANOMALY APT DEMO FILE G0065 T1218_005 {
   meta:
      description = "VBScript cloaked as Favicon file used in Leviathan incident"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets"
      date = "2017-10-18 11:44:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "39c952c7e14b6be5a9cb1be3f05eafa22e1115806e927f4e2dc85d609bc0eb36"
      tags = "ANOMALY, APT, DEMO, FILE, G0065, T1218_005"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "myxml = '<?xml version=\"\"1.0\"\" encoding=\"\"UTF-8\"\"?>';myxml = myxml +'<root>" ascii
      $x2 = ".Run \"taskkill /im mshta.exe" ascii
      $x3 = "<script language=\"VBScript\">Window.ReSizeTo 0, 0 : Window.moveTo -2000,-2000 :" ascii
      $s1 = ".ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\") &" ascii
      $s2 = ".ExpandEnvironmentStrings(\"%temp%\") & " ascii
   condition: 
      filesize < 100KB and ( uint16 ( 0 ) == 0x733c and 1 of ( $x* ) ) or ( 3 of them )
}