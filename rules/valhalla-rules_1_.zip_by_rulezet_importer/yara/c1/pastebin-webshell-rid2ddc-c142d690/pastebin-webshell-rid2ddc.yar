rule Pastebin_Webshell_RID2DDC : DEMO SCRIPT T1505_003 T1569_002 WEBSHELL {
   meta:
      description = "Detects a web shell that downloads content from pastebin.com https://blog.sucuri.net/2015/01/website-backdoors-leverage-the-pastebin-service.html"
      author = "Florian Roth"
      reference = "https://blog.sucuri.net/2015/01/website-backdoors-leverage-the-pastebin-service.html"
      date = "2015-01-13 10:49:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, SCRIPT, T1505_003, T1569_002, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "file_get_contents(\"http://pastebin.com" ascii
      $s1 = "xcurl('http://pastebin.com/download.php" ascii
      $s2 = "xcurl('http://pastebin.com/raw.php" ascii
      $x0 = "if($content){unlink('evex.php');" ascii
      $x1 = "$fh2 = fopen(\"evex.php\", 'a');" ascii
      $y0 = "file_put_contents($pth" ascii
      $y1 = "echo \"<login_ok>" ascii
      $y2 = "str_replace('* @package Wordpress',$temp" ascii
   condition: 
      1 of ( $s* ) or all of ( $x* ) or all of ( $y* )
}