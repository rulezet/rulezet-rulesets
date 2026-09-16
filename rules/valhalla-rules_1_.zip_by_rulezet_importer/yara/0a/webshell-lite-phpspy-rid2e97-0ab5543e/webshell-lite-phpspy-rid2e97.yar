rule Webshell_lite_PHPSPY_RID2E97 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, PHPSPY.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:21:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "42f211cec8032eb0881e87ebdb3d7224"
      hash2 = "0712e3dc262b4e1f98ed25760b206836"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "<input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['comma" 
      $s7 = "echo $msg=@copy($_FILES['uploadmyfile']['tmp_name'],\"\".$uploaddir.\"/\".$_FILE" 
      $s8 = "<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; " 
   condition: 
      2 of them
}