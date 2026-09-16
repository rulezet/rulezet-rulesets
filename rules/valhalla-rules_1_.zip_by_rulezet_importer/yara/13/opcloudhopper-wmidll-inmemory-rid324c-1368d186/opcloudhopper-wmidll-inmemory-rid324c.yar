rule OpCloudHopper_WmiDLL_inMemory_RID324C : APT DEMO {
   meta:
      description = "Malware related to Operation Cloud Hopper - Page 25"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07 13:59:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "wmi.dll 2>&1" ascii
   condition: 
      all of them
}