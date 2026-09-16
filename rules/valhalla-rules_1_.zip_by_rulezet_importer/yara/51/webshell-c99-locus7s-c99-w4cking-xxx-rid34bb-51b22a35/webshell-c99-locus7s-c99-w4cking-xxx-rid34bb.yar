rule Webshell_c99_locus7s_c99_w4cking_xxx_RID34BB : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:43:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c34adbc8fd8d908cbb341734830f971"
      hash2 = "ef43fef943e9df90ddb6257950b3538f"
      hash3 = "ae025c886fbe7f9ed159f49593674832"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$res = @shell_exec($cfe);" fullword
      $s8 = "$res = @ob_get_contents();" fullword
      $s9 = "@exec($cfe,$res);" fullword
   condition: 
      2 of them
}