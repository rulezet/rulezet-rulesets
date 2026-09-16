rule EXPL_React_Server_CVE_2025_55182_POC_Dec25_RID344A : CVE_2025_55182 DEMO EXPLOIT T1505_003 {
   meta:
      description = "Detects in-memory webshell indicators related to the proof-of-concept code for the React Server Remote Code Execution Vulnerability (CVE-2025-55182)"
      author = "Florian Roth"
      reference = "https://x.com/pyn3rd/status/1996840827897954542/photo/1"
      date = "2025-12-05 15:24:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_55182, DEMO, EXPLOIT, T1505_003"
      minimum_yara = "3.5.0"
      
   strings:
      $xs1 = "{const cmd=p.query.cmd;if(!cmd)(s.writeHead(400);" 
      $s1 = ";if(p.pathname==" 
      $s2 = ".writeHead(400);" 
      $s3 = ".writeHead(200,{'Content-Type':" 
      $s4 = ".execSync(" 
      $s5 = ",stdio:'pipe'})" 
   condition: 
      1 of ( $x* ) or all of ( $s* )
}