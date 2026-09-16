rule SUSP_JS_NPM_Sha1_Hulud_Nov25_RID30A8 : DEMO SUSP T1059_007 {
   meta:
      description = "Detects suspicious indicators for Sha1 Hulud worm"
      author = "Marius Benthin"
      reference = "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
      date = "2025-11-24 12:49:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-12-15"
      tags = "DEMO, SUSP, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Sha1-Hulud:\\x" 
      $x2 = "SHA1HULUD\"`" 
   condition: 
      filesize < 20MB and 1 of them
}