rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_1_RID33F3 : APT DEMO G0032 MAL NK {
   meta:
      description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
      date = "2019-04-13 15:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d77fdabe17cdba62a8e728cbe6c740e2c2e541072501f77988674e07a05dfb39"
      tags = "APT, DEMO, G0032, MAL, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "www.naver.com" fullword ascii
      $s2 = "PolarSSL Test CA0" fullword ascii
   condition: 
      filesize < 1000KB and all of them
}