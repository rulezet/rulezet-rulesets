rule WebShell_Generic_PHP_6_RID2F1F : DEMO GEN SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files c0derz shell [csh] v. 0.1.1 release.php, CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:43:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "335a0851304acedc3f117782b61479bbc0fd655a"
      hash2 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
      hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
      tags = "DEMO, GEN, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "@eval(stripslashes($_POST['phpcode']));" fullword
      $s5 = "echo shell_exec($com);" fullword
      $s7 = "if($sertype == \"winda\"){" fullword
      $s8 = "function execute($com)" fullword
      $s12 = "echo decode(execute($cmd));" fullword
      $s15 = "echo system($com);" fullword
   condition: 
      4 of them
}