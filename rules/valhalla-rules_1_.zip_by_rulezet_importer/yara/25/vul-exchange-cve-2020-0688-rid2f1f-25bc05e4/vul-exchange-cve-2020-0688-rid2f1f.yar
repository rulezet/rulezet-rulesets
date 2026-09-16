rule VUL_Exchange_CVE_2020_0688_RID2F1F : CVE_2020_0688 DEMO VULN {
   meta:
      description = "Detects static validation key used by Exchange server in web.config"
      author = "Florian Roth"
      reference = "https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys"
      date = "2020-02-26 11:43:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2020_0688, DEMO, VULN"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "<?xml " 
      $x1 = "<machineKey validationKey=\"CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF\"" ascii wide
   condition: 
      filesize <= 300KB and $h1 at 0 and $x1
}