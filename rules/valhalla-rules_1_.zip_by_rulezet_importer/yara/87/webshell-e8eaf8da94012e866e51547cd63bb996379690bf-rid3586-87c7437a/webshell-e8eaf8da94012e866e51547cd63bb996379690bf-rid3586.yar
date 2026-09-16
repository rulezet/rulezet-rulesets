rule Webshell_e8eaf8da94012e866e51547cd63bb996379690bf_RID3586 : DEMO FILE SCRIPT T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:16:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "027544baa10259939780e97dc908bd43f0fb940510119fc4cce0883f3dd88275"
      tags = "DEMO, FILE, SCRIPT, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "@exec('./bypass/ln -s /etc/passwd 1.php');" fullword ascii
      $x2 = "echo \"<iframe src=mysqldumper/index.php width=100% height=100% frameborder=0></iframe> \";" fullword ascii
      $x3 = "@exec('tar -xvf mysqldumper.tar.gz');" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x213c and filesize < 100KB and 1 of ( $x* ) ) or ( 2 of them )
}