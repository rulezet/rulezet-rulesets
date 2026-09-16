rule Empire_Invoke_InveighRelay_Gen_RID32DD : DEMO GEN SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - from files Invoke-InveighRelay.ps1, Invoke-InveighRelay.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 14:23:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash2 = "21b90762150f804485219ad36fa509aeda210d46453307a9761c816040312f41"
      tags = "DEMO, GEN, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$inveigh.SMBRelay_failed_list.Add(\"$HTTP_NTLM_domain_string\\$HTTP_NTLM_user_string $SMBRelayTarget\")" fullword ascii
      $s2 = "$NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 200KB and 1 of them ) or all of them
}