rule MSBuild_Mimikatz_Execution_via_XML_RID3448 : DEMO S0002 SUSP T1003 T1127_001 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Detects an XML that executes Mimikatz on an endpoint via MSBuild"
      author = "Florian Roth"
      reference = "https://gist.github.com/subTee/c98f7d005683e616560bda3286b6a0d8#file-katz-xml"
      date = "2016-10-07 15:23:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, S0002, SUSP, T1003, T1127_001, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "<Project ToolsVersion=" ascii
      $x2 = "</SharpLauncher>" fullword ascii
      $s1 = "\"TVqQAAMAAAA" ascii
      $s2 = "System.Convert.FromBase64String(" ascii
      $s3 = ".Invoke(" ascii
      $s4 = "Assembly.Load(" ascii
      $s5 = ".CreateInstance(" ascii
   condition: 
      all of them
}