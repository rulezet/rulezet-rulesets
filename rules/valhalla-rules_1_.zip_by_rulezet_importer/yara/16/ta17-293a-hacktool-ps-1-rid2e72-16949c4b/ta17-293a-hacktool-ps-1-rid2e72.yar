rule TA17_293A_Hacktool_PS_1_RID2E72 : APT DEMO SCRIPT T1059_001 {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21 11:14:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "72a28efb6e32e653b656ca32ccd44b3111145a695f6f6161965deebbdc437076"
      tags = "APT, DEMO, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "$HashFormat = '$krb5tgs$23$*ID#124_DISTINGUISHED NAME: CN=fakesvc,OU=Service,OU=Accounts,OU=EnterpriseObjects,DC=asdf,DC=pd,DC=f" ascii
      $x2 = "} | Where-Object {$_.SamAccountName -notmatch 'krbtgt'} | Get-SPNTicket @GetSPNTicketArguments" fullword ascii
   condition: 
      ( filesize < 80KB and 1 of them )
}