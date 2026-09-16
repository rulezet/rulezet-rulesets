rule Webshell_php_dns_RID2D92 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file dns.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:37:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii
      $s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii
      $s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii
      $s4 = "foreach (array_keys($types) as $t) {" fullword ascii
   condition: 
      filesize < 15KB and all of them
}