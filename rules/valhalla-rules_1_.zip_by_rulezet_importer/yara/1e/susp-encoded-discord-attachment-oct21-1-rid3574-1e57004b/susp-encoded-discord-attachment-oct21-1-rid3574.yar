rule SUSP_Encoded_Discord_Attachment_Oct21_1_RID3574 : DEMO SUSP T1027 {
   meta:
      description = "Detects suspicious encoded URL to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-10-12 16:13:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP, T1027"
      minimum_yara = "3.5.0"
      
   strings:
      $enc_b01 = "Y2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRz" ascii wide
      $enc_b02 = "Nkbi5kaXNjb3JkYXBwLmNvbS9hdHRhY2htZW50c" ascii wide
      $enc_b03 = "jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudH" ascii wide
      $enc_b04 = "AGMAZABuAC4AZABpAHMAYwBvAHIAZABhAHAAcAAuAGMAbwBtAC8AYQB0AHQAYQBjAGgAbQBlAG4AdABz" ascii wide
      $enc_b05 = "BjAGQAbgAuAGQAaQBzAGMAbwByAGQAYQBwAHAALgBjAG8AbQAvAGEAdAB0AGEAYwBoAG0AZQBuAHQAc" ascii wide
      $enc_b06 = "AYwBkAG4ALgBkAGkAcwBjAG8AcgBkAGEAcABwAC4AYwBvAG0ALwBhAHQAdABhAGMAaABtAGUAbgB0AH" ascii wide
      $enc_h01 = "63646E2E646973636F72646170702E636F6D2F6174746163686D656E7473" ascii wide
      $enc_h02 = "63646e2e646973636f72646170702e636f6d2f6174746163686d656e7473" ascii wide
      $enc_r01 = "stnemhcatta/moc.ppadrocsid.ndc" ascii wide
   condition: 
      filesize < 5000KB and 1 of them
}