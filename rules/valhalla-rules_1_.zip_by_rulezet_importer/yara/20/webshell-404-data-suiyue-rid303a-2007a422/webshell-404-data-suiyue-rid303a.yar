rule Webshell_404_data_suiyue_RID303A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 404.jsp, data.jsp, suiyue.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:30:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
      hash2 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+" 
   condition: 
      all of them
}