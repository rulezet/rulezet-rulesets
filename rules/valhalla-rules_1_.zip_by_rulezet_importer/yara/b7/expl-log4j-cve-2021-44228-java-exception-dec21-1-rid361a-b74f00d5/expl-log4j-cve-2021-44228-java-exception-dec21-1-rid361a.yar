rule EXPL_Log4j_CVE_2021_44228_JAVA_Exception_Dec21_1_RID361A : CVE_2021_44228 DEMO EXPLOIT {
   meta:
      description = "Detects exceptions found in server logs that indicate an exploitation attempt of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b"
      date = "2021-12-12 16:41:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_44228, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $xa1 = "header with value of BadAttributeValueException: " 
      $sa1 = ".log4j.core.net.JndiManager.lookup(JndiManager" 
      $sa2 = "Error looking up JNDI resource" 
   condition: 
      $xa1 or all of ( $sa* )
}