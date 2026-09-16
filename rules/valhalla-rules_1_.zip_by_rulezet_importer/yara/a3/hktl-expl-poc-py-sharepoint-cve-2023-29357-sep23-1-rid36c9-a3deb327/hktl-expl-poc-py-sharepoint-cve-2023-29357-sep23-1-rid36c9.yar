rule HKTL_EXPL_POC_PY_SharePoint_CVE_2023_29357_Sep23_1_RID36C9 : CVE_2023_29357 DEMO EXPLOIT HKTL SCRIPT T1059_006 {
   meta:
      description = "Detects a Python POC to exploit CVE-2023-29357 on Microsoft SharePoint servers"
      author = "Florian Roth"
      reference = "https://github.com/Chocapikk/CVE-2023-29357"
      date = "2023-09-30 17:10:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-10-01"
      tags = "CVE_2023_29357, DEMO, EXPLOIT, HKTL, SCRIPT, T1059_006"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')" 
   condition: 
      filesize < 30KB and $x1
}