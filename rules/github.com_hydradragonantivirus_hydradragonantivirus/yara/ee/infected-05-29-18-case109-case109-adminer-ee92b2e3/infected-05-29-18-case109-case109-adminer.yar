rule _infected_05_29_18_case109_case109_adminer {
  meta:
    description = "case109 - file adminer.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "82faa945d041fdc0d98181ea05618ec8f22a27910bb1d461d8ef8f79527af0e5"

  strings:
    $x1  = "as$z=>$X){if($z!=\"\"&&$X>1){echo($rc?\"<p>\":\" \").\"<a href='\".h(ME).\"dump=\".urlencode(\"$z%\").\"'>\".h($z).\"</a>\";$rc=" ascii
    $x2  = "as$Wc=>$X){if($X[0]<$kg)unset($Vc[$Wc]);}}$Uc=&$Vc[$c->bruteForceKey()];if(!$Uc)$Uc=array($kg+30*60,0);$Uc[1]++;$_f=serialize($V" ascii
    $x3  = "as$k=>$S){$of=h(ME).\"db=\".urlencode($k);$v=h(\"Db-\".$k);echo\"<tr\".odd().\">\".(support(\"database\")?\"<td>\".checkbox(\"db" ascii
    $x4  = "as$V=>$G){if($G!==null){if($rc){echo\"<p id='logins' onmouseover='menuOver(this, event);' onmouseout='menuOut(this);'>\\n\";$rc=" ascii
    $s5  = "connect_error(){global$c,$g,$T,$l,$Gb;if(DB!=\"\"){header(\"HTTP/1.1 404 Not Found\");page_header(lang(31).\": \".h(DB),lang(98)" ascii
    $s6  = "EmailProcess($Z,$p)){if($_POST[\"save\"]||$_POST[\"delete\"]){$J=true;$na=0;$P=array();if(!$_POST[\"delete\"]){foreach($e" fullword ascii
    $s7  = "';if(!$L[\"hashed\"]){echo'<script type=\"text/javascript\">typePassword(document.getElementById(\\'pass\\'));</script>';}echo" fullword ascii
    $s8  = "password_file($i){$pc=get_temp_dir().\"/adminer.key\";$K=@file_get_contents($pc);if($K||!$i)return$K;$q=@fopen($pc,\"w\");if($q)" ascii
    $s9  = "password_file($i){$pc=get_temp_dir().\"/adminer.key\";$K=@file_get_contents($pc);if($K||!$i)return$K;$q=@fopen($pc,\"w\");if($q)" ascii
    $s10 = "($X))$fd++;}queries_redirect(ME.\"processlist=\",lang(218,$fd),$fd||!$_POST[\"kill\"]);}page_header(lang(102),$l);echo'" fullword ascii
    $s11 = "as$X){if($X[1]!=\"USAGE\")$_c[\"$C[2]$X[2]\"][$X[1]]=true;if(preg_match('~ WITH GRANT OPTION~',$L[0]))$_c[\"$C[2]$X[2]\"][\"GRAN" ascii
    $s12 = "doc_link($De){global$y,$g;$Lg=array('sql'=>\"http://dev.mysql.com/doc/refman/\".substr($g->server_info,0,3).\"/en/\",'sqlite'=>" ascii
    $s13 = "';}elseif(isset($_GET[\"dump\"])){$b=$_GET[\"dump\"];if($_POST&&!$l){$jb=\"\";foreach(array(\"output\",\"format\",\"db_style\"," ascii
    $s14 = "selectLengthProcess(){return(isset($_GET[\"text_length\"])?$_GET[\"text_length\"]:\"100\");}function" fullword ascii
    $s15 = "name(){return\"<a href='https://www.adminer.org/' target='_blank' id='h1'>Adminer</a>\";}function" fullword ascii
    $s16 = "<a href=\"https://www.adminer.org/#download\" target=\"_blank\" id=\"version\">',(version_compare($fa,$_COOKIE[\"adminer_version" ascii
    $s17 = "<a href=\"https://www.adminer.org/#download\" target=\"_blank\" id=\"version\">',(version_compare($fa,$_COOKIE[\"adminer_version" ascii
    $s18 = "add_invalid_login(){global$c;$pc=get_temp_dir().\"/adminer.invalid\";$q=@fopen($pc,\"r+\");if(!$q){$q=@fopen($pc,\"w\");if(!$q)r" ascii
    $s19 = "* @license http://www.gnu.org/licenses/gpl-2.0.html GNU General Public License, version 2 (one or other)" fullword ascii
    $s20 = "(DB!=\"\"?$g->select_db(DB):isset($_GET[\"sql\"])||isset($_GET[\"dump\"])||isset($_GET[\"database\"])||isset($_GET[\"processlist" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1000KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}