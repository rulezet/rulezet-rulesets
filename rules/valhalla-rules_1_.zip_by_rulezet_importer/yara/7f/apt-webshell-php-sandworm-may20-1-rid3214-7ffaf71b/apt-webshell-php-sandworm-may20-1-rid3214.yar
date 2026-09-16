rule APT_WEBSHELL_PHP_Sandworm_May20_1_RID3214 : APT DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects GIF header PHP webshell used by Sandworm on compromised machines"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28 13:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      tags = "APT, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "GIF89a <?php $" ascii
      $s1 = "str_replace(" ascii
   condition: 
      filesize < 10KB and $h1 at 0 and $s1
}