rule EquationGroup_estopmoonlit {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file estopmoonlit"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "707ecc234ed07c16119644742ebf563b319b515bf57fd43b669d3791a1c5e220"
      id = "7ae7a8b7-5e27-5604-8c57-6d60ffa0fb72"
   strings:
      $x1 = "[+] shellcode prepared, re-executing" fullword ascii
      $x2 = "[-] kernel not vulnerable: prctl" fullword ascii
      $x3 = "[-] shell failed" fullword ascii
      $x4 = "[!] selinux apparently enforcing.  Continue [y|n]? " fullword ascii
   condition:
      filesize < 250KB and 1 of them
}