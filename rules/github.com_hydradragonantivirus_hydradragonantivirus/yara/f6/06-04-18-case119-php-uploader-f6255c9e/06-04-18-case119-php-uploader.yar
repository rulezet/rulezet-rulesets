rule _06_04_18_case119_php_uploader {
  meta:
    description = "case119 - file db.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-04"
    hash1       = "0867e84e4d9d94a435d828b1464c39972455acf472e4be208ced097656dc338e"

  strings:
    $s1 = "<?php error_reporting(0);echo(\"Form#0x2515\");if(isset($_GET[\"u\"])){echo'<form ction=\"\" method=\"post\" enctype=\"multipart" ascii
    $s2 = "Upload!!!</b><br><br>';}else{echo'<b>Failed :@ :@ !!!</b><br><br>';}};};" fullword ascii
    $s3 = "<?php error_reporting(0);echo(\"Form#0x2515\");if(isset($_GET[\"u\"])){echo'<form ction=\"\" method=\"post\" enctype=\"multipart" ascii
    $s4 = "a\" name=\"uploader\" id=\"uploader\">';echo'<input type=\"file\" name=\"file\" size=\"50\"><input name=\"_upl\" type=\"submit\"" ascii
    $s5 = "e=\"Upload\"></form>';if($_POST['_upl']==\"Upload\"){if(@copy($_FILES['file']['tmp_name'],$_FILES['file']['name'])){echo'<b>Succ" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}