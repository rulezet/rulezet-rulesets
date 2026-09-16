rule BCKDR_XZUtil_KillSwitch_CVE_2024_3094_Mar24_1_RID358B : CVE_2024_3094 DEMO {
   meta:
      description = "Detects kill switch used by the backdoored XZ library (xzutil) CVE-2024-3094."
      author = "Florian Roth"
      reference = "https://gist.github.com/q3k/af3d93b6a1f399de28fe194add452d01?permalink_comment_id=5006558#gistcomment-5006558"
      date = "2024-03-30 16:17:41"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2024_3094, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "yolAbejyiejuvnup=Evjtgvsh5okmkAvj" 
   condition: 
      $x1
}