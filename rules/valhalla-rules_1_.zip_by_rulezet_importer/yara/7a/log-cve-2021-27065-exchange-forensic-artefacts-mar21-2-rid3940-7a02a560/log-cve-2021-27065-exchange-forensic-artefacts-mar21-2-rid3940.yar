rule LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_2_RID3940 : CVE_2021_27065 DEMO G0125 LOG {
   meta:
      description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
      author = "Florian Roth"
      reference = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
      date = "2021-03-10 18:55:51"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_27065, DEMO, G0125, LOG"
      minimum_yara = "3.5.0"
      
   strings:
      $sr1 = /GET \/rpc\/ &CorrelationID=<empty>;&RequestId=[^\n]{40,600} (200|301|302)/ 
   condition: 
      $sr1
}