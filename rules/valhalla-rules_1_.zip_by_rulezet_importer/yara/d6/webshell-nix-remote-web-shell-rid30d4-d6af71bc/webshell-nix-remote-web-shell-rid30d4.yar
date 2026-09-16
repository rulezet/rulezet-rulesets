rule Webshell_NIX_REMOTE_WEB_SHELL_RID30D4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, KAdot Universal Shell v0.1.6.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:56:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f3ca29b7999643507081caab926e2e74"
      hash2 = "527cf81f9272919bf872007e21c4bdda"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type=" 
      $s2 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword
      $s6 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword
      $s7 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword
   condition: 
      2 of them
}