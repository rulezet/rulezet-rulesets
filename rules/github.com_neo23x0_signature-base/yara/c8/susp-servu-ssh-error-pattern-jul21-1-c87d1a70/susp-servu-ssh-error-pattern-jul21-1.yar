rule SUSP_ServU_SSH_Error_Pattern_Jul21_1 {
   meta:
      description = "Detects suspicious SSH component exceptions that could be an indicator of exploitation attempts as described in advisory addressing CVE-2021-35211 in ServU services"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35211#FAQ"
      date = "2021-07-12"
      score = 60
      id = "1a89f0b0-445c-5867-94cd-f07ba1becad6"
   strings:
      $s1 = "EXCEPTION: C0000005;" ascii
      $s2 = "CSUSSHSocket::ProcessReceive();" ascii
   condition:
      filename == "DebugSocketlog.txt"
      and all of ($s*)
}