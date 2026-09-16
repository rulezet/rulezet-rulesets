rule MAL_3CXDesktopApp_MacOS_UpdateAgent_Mar23_RID35BA : DEMO MACOS MAL {
   meta:
      description = "Detects 3CXDesktopApp MacOS UpdateAgent backdoor component"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/patrickwardle/status/1641692164303515653?s=20"
      date = "2023-03-30 16:25:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MACOS, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "/3CX Desktop App/.main_storage" ascii
      $x1 = ";3cx_auth_token_content=%s;__tutma=true" 
      $s1 = "\"url\": \"https://" 
      $s3 = "/dev/null" 
      $s4 = "\"AccountName\": \"" 
   condition: 
      uint16 ( 0 ) == 0xfeca and filesize < 6MB and ( 1 of ( $x* ) or ( $a1 and all of ( $s* ) ) ) or all of them
}