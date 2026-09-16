rule HTA_with_WScript_Shell_RID2F8B : DEMO SCRIPT SUSP {
   meta:
      description = "Detects WScript Shell in HTA"
      author = "Florian Roth"
      reference = "https://twitter.com/msftmmpc/status/877396932758560768"
      date = "2017-06-21 12:01:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
      tags = "DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<hta:application windowstate=\"minimize\"/>" 
      $s2 = "<script>var b=new ActiveXObject(\"WScript.Shell\");" ascii
   condition: 
      all of them
}