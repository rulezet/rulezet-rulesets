rule FIN7_Dropper_Aug17_RID2D44 : DEMO FILE G0046 MAL OFFICE RUSSIA {
   meta:
      description = "Detects Word Dropper from Proofpoint FIN7 Report"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor"
      date = "2017-08-04 10:24:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c91642c0a5a8781fff9fd400bff85b6715c96d8e17e2d2390c1771c683c7ead9"
      hash2 = "cf86c7a92451dca1ebb76ebd3e469f3fa0d9b376487ee6d07ae57ab1b65a86f8"
      tags = "DEMO, FILE, G0046, MAL, OFFICE, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "tpircsj:e/ b// exe.tpircsw\" rt/" fullword ascii
      $s1 = "Scripting.FileSystemObject$" fullword ascii
      $s2 = "PROJECT.THISDOCUMENT.AUTOOPEN" fullword wide
      $s3 = "Project.ThisDocument.AutoOpen" fullword wide
      $s4 = "\\system3" ascii
      $s5 = "ShellV" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xcfd0 and filesize < 700KB and 1 of ( $x* ) or all of ( $s* ) )
}