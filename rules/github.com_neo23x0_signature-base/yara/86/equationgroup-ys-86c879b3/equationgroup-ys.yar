rule EquationGroup_ys {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ys.auto"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a6387307d64778f8d9cfc60382fdcf0627cde886e952b8d73cc61755ed9fde15"
      id = "abd120e7-23f8-530e-b21e-c50a2b571332"
   strings:
      $x1 = "EXPLOIT_SCRIPME=\"$EXPLOIT_SCRIPME\"" fullword ascii
      $x3 = "DEFTARGET=`head /current/etc/opscript.txt 2>/dev/null | grepip 2>/dev/null | head -1`" fullword ascii
      $x4 = "FATAL ERROR: -x port and -n port MUST NOT BE THE SAME." fullword ascii
   condition:
      filesize < 250KB and 1 of them
}