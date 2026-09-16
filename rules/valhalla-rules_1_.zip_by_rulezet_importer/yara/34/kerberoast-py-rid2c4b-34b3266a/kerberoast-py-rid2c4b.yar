rule kerberoast_PY_RID2C4B : DEMO HKTL SCRIPT T1558_003 {
   meta:
      description = "Semiautomatically generated YARA rule - file kerberoast.py"
      author = "Florian Roth"
      reference = "https://github.com/skelsec/PyKerberoast"
      date = "2016-05-21 09:43:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "73155949b4344db2ae511ec8cab85da1ccbf2dfec3607fb9acdc281357cdf380"
      tags = "DEMO, HKTL, SCRIPT, T1558_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "newencserverticket = kerberos.encrypt(key, 2, encoder.encode(decserverticket), nonce)" fullword ascii
      $s2 = "key = kerberos.ntlmhash(args.password)" fullword ascii
      $s3 = "help='the password used to decrypt/encrypt the ticket')" fullword ascii
      $s4 = "newencserverticket = kerberos.encrypt(key, 2, e, nonce)" fullword ascii
   condition: 
      2 of them
}