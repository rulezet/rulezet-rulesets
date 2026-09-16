rule EXPL_MAL_MalDoc_OBFUSCT_MHTML_Sep21_1_RID32E2 : CVE_2021_40444 DEMO EXPLOIT MAL OBFUS OFFICE {
   meta:
      description = "Detects suspicious office reference files including an obfuscated MHTML reference exploiting CVE-2021-40444"
      author = "Florian Roth"
      reference = "https://twitter.com/decalage2/status/1438946225190014984?s=20"
      date = "2021-09-18 14:24:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_40444, DEMO, EXPLOIT, MAL, OBFUS, OFFICE"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "<?xml " ascii wide
      $s1 = "109;&#104;&#116;&#109;&#108;&#58;&#104;&#116;&#109;&#108" ascii wide
   condition: 
      filesize < 25KB and all of them
}