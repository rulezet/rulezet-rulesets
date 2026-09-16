rule Webshell_Txt_php_2_RID2E1E : CHINA DEMO T1016 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file php.html"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:00:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1016, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "function connect($dbhost, $dbuser, $dbpass, $dbname='') {" fullword ascii
      $s2 = "scookie('loginpass', '', -86400 * 365);" fullword ascii
      $s3 = "<title><?php echo $act.' - '.$_SERVER['HTTP_HOST'];?></title>" fullword ascii
      $s4 = "Powered by <a title=\"Build 20130112\" href=\"http://www.4ngel.net\" target=\"_b" ascii
      $s5 = "formhead(array('title'=>'Execute Command', 'onsubmit'=>'g(\\'shell\\',null,this." ascii
      $s6 = "secparam('IP Configurate',execute('ipconfig -all'));" fullword ascii
      $s7 = "secparam('Hosts', @file_get_contents('/etc/hosts'));" fullword ascii
      $s8 = "p('<p><a href=\"http://w'.'ww.4'.'ng'.'el.net/php'.'sp'.'y/pl'.'ugin/\" target=" ascii
   condition: 
      filesize < 100KB and 4 of them
}