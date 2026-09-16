rule SUSP_Base64_Encoded_Hacktool_Dev_RID32C3 : DEMO SUSP T1132_001 {
   meta:
      description = "Detects a suspicious base64 encoded keyword"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1270626274826911744"
      date = "2020-06-10 14:19:01"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP, T1132_001"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "QGdlbnRpbGtpd2" ascii wide
      $ = "BnZW50aWxraXdp" ascii wide
      $ = "AZ2VudGlsa2l3a" ascii wide
      $ = "QGhhcm1qMH" ascii wide
      $ = "BoYXJtajB5" ascii wide
      $ = "AaGFybWowe" ascii wide
      $ = "IEBzdWJ0ZW" ascii wide
      $ = "BAc3VidGVl" ascii wide
      $ = "gQHN1YnRlZ" ascii wide
   condition: 
      filesize < 6000KB and 1 of them
}