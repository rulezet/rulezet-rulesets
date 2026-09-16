rule SUSP_JS_NPM_SetupScript_Nov25_RID3180 : DEMO SUSP T1059_007 {
   meta:
      description = "Detects suspicious JavaScript which exits silently and checks operating system"
      author = "Marius Benthin"
      reference = "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
      date = "2025-11-24 13:25:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-12-15"
      tags = "DEMO, SUSP, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "require('child_process')" 
      $sa2 = "process.platform ===" 
      $sb1 = "().catch((e" 
      $sb2 = "process.exit(0)" 
   condition: 
      filesize < 100KB and all of ( $sa* ) and $sb1 in ( filesize - 50 .. filesize ) and $sb2 in ( filesize - 30 .. filesize )
}