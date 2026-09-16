rule Webshell_r57shell_SnIpEr_EgY_SpIdEr_RID3416 : CRIME DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:15:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ae025c886fbe7f9ed159f49593674832"
      hash2 = "911195a9b7c010f61b66439d9048f400"
      hash3 = "697dae78c040150daff7db751fc0c03c"
      tags = "CRIME, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo sr(15,\"<b>\".$lang[$language.'_text58'].$arrow.\"</b>\",in('text','mk_name" 
      $s3 = "echo sr(15,\"<b>\".$lang[$language.'_text21'].$arrow.\"</b>\",in('checkbox','nf1" 
      $s9 = "echo sr(40,\"<b>\".$lang[$language.'_text26'].$arrow.\"</b>\",\"<select size=" 
   condition: 
      all of them
}