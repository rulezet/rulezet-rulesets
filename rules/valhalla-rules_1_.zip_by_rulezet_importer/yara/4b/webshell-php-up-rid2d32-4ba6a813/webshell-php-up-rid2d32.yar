rule Webshell_php_up_RID2D32 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file up.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:21:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);" fullword
      $s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {" fullword
      $s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];" fullword
   condition: 
      2 of them
}