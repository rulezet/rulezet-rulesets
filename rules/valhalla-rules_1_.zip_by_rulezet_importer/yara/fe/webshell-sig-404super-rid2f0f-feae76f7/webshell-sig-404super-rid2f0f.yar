rule Webshell_sig_404super_RID2F0F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file 404super.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 11:41:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "$i = pack('c*', 0x70, 0x61, 99, 107);" fullword
      $s6 = "    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631')," fullword
      $s7 = "//http://require.duapp.com/session.php" fullword
      $s8 = "if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}" fullword
      $s12 = "//define('pass','123456');" fullword
      $s13 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO" 
   condition: 
      1 of them
}