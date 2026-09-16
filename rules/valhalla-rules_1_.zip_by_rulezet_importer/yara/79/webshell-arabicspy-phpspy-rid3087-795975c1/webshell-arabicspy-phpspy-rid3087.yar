rule Webshell_Arabicspy_PHPSPY_RID3087 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files shell.php, phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, arabicspy.php, PHPSPY.php, hkrkoz.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:43:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
      hash2 = "42f211cec8032eb0881e87ebdb3d7224"
      hash3 = "40a1f840111996ff7200d18968e42cfe"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$mainpath_info           = explode('/', $mainpath);" fullword
      $s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d" 
   condition: 
      all of them
}