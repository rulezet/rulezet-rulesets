rule EXPL_Office_TemplateInjection_Aug19_RID3419 : DEMO EXPLOIT OFFICE T1203 T1221 T1566_001 {
   meta:
      description = "Detects possible template injections in Office documents, particularly those that load content from external sources"
      author = "Florian Roth"
      reference = "https://attack.mitre.org/techniques/T1221/"
      date = "2019-08-22 15:16:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-20"
      tags = "DEMO, EXPLOIT, OFFICE, T1203, T1221, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = /attachedTemplate" Target="http[s]?:\/\/[^"]{4,60}/ ascii
      $fp1 = ".sharepoint.com" 
      $fp2 = ".office.com" 
   condition: 
      filesize < 20MB and $x1 and not 1 of ( $fp* )
}