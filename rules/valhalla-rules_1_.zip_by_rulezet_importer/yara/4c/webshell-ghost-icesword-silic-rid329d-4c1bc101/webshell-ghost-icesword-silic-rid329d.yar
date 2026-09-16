rule Webshell_Ghost_Icesword_Silic_RID329D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files ghost_source.php, icesword.php, silic.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:12:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6e20b41c040efb453d57780025a292ae"
      hash2 = "437d30c94f8eef92dc2f064de4998695"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $" 
      $s6 = "if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST[" 
   condition: 
      all of them
}