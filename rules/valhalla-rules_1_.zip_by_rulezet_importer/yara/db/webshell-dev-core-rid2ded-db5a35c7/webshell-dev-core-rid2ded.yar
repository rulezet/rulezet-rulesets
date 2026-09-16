rule Webshell_dev_core_RID2DED : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file dev_core.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 10:52:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if (strpos($_SERVER['HTTP_USER_AGENT'], 'EBSD') == false) {" fullword
      $s9 = "setcookie('key', $_POST['pwd'], time() + 3600 * 24 * 30);" fullword
      $s10 = "$_SESSION['code'] = _REQUEST(sprintf(\"%s?%s\",pack(\"H*\",'6874" 
      $s11 = "if (preg_match(\"/^HTTP\\/\\d\\.\\d\\s([\\d]+)\\s.*$/\", $status, $matches))" 
      $s12 = "eval(gzuncompress(gzuncompress(Crypt::decrypt($_SESSION['code'], $_C" 
      $s15 = "if (($fsock = fsockopen($url2['host'], 80, $errno, $errstr, $fsock_timeout))" 
   condition: 
      1 of them
}