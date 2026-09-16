rule SUSP_Msdt_Artefact_Jun22_2_RID305D : CVE_2022_30190 DEMO FILE SUSP {
   meta:
      description = "Detects suspicious pattern in msdt diagnostics log (e.g. CVE-2022-30190)"
      author = "Christian Burkard"
      reference = "https://twitter.com/nas_bench/status/1531718490494844928"
      date = "2022-06-01 12:36:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-07-29"
      tags = "CVE_2022_30190, DEMO, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "<ScriptError><Data id=\"ScriptName\" name=\"Script\">TS_ProgramCompatibilityWizard.ps1" ascii
      $x1 = "/../../" ascii
      $x2 = "$(Invoke-Expression" ascii
      $x3 = "$(IEX(" ascii nocase
   condition: 
      uint32 ( 0 ) == 0x6D783F3C and $a1 and 1 of ( $x* )
}