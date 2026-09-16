rule Webshell_webshells_new_code_RID3212 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file code.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:49:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi" 
      $s7 = "$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO" 
      $s10 = "if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_" 
      $s14 = "Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:" 
      $s17 = "<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm" 
   condition: 
      1 of them
}