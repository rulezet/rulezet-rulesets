rule WebShell_Generic_PHP_9_RID2F22 : DEMO GEN SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files KAdot Universal Shell v0.1.6.php, KAdot_Universal_Shell_v0.1.6.php, KA_uShell 0.1.6.php"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2014-04-06 11:44:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-06"
      hash1 = "2266178ad4eb72c2386c0a4d536e5d82bb7ed6a2"
      hash2 = "0daed818cac548324ad0c5905476deef9523ad73"
      tags = "DEMO, GEN, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $ = { 3a 3c 62 3e 22 20 2e 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 24 5f 50 4f 53 54 5b 27 74 6f 74 27 5d 29 2e 20 22 3c 2f 62 3e 22 3b } 
      $ = { 69 66 20 28 69 73 73 65 74 28 24 5f 50 4f 53 54 5b 27 77 71 27 5d 29 20 26 26 20 24 5f 50 4f 53 54 5b 27 77 71 27 5d 3c 3e 22 22 29 20 7b } 
      $ = { 70 61 73 73 74 68 72 75 28 24 5f 50 4f 53 54 5b 27 63 27 5d 29 3b } 
      $ = { 3c 69 6e 70 75 74 20 74 79 70 65 3d 22 72 61 64 69 6f 22 20 6e 61 6d 65 3d 22 74 61 63 22 20 76 61 6c 75 65 3d 22 31 22 3e 42 36 34 20 44 65 63 6f 64 65 3c 62 72 3e } 
   condition: 
      1 of them
}