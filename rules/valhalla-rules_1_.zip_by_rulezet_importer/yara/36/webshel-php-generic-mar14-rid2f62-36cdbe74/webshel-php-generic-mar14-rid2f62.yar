rule WEBSHEL_PHP_Generic_Mar14_RID2F62 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Detects PHP webshell"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:54:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-05-12"
      hash1 = "f51a5c5775d9cca0b137ddb28ff3831f4f394b7af6f6a868797b0df3dcdb01ba"
      hash2 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"
      hash3 = "9ecdb14b41785c779d9721e11bf9e1b7e35611015f4aabf9a1f54a82eaa0725c"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo sr(15,\"<b>\".$lang[$language.'_text" 
      $s1 = ".$arrow.\"</b>\",in('text','" 
   condition: 
      2 of them
}