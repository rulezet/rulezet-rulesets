rule TTP_XOR_QUAD_CurrentVersionRun_9bac {
  strings:
    $key_9bac = { c8 c3 [2] ec cd [2] c7 e1 [2] e9 c3 [2] fd d8 [2] f2 c2 [2] ec df [2] ee de [2] f5 d8 [2] e9 df [2] f5 f0 }

  condition:
    any of them
}