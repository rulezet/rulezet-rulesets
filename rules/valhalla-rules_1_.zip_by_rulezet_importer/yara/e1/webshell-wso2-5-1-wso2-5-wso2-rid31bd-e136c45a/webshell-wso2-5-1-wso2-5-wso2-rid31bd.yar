rule Webshell_wso2_5_1_wso2_5_wso2_RID31BD : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files wso2.5.1.php, wso2.5.php, wso2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:35:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7c8e5d31aad28eb1f0a9a53145551e05"
      hash2 = "cbc44fb78220958f81b739b493024688"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec" 
      $s8 = ".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na" 
   condition: 
      all of them
}