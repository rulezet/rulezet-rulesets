rule CN_Honker_Webshell_PHP_php1_RID311C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php1.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:08:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "$sendbuf = \"site exec \".$_POST[\"SUCommand\"].\"\\r\\n\";" fullword ascii
      $s8 = "elseif(function_exists('passthru')){@ob_start();@passthru($cmd);$res = @ob_get_c" ascii
      $s18 = "echo Exec_Run($perlpath.' /tmp/spider_bc '.$_POST['yourip'].' '.$_POST['yourport" ascii
   condition: 
      filesize < 621KB and all of them
}