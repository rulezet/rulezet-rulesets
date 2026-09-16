rule TTP_XOR_QUAD_CurrentVersionRun_85a3 {
  strings:
    $key_85a3 = { d6 cc [2] f2 c2 [2] d9 ee [2] f7 cc [2] e3 d7 [2] ec cd [2] f2 d0 [2] f0 d1 [2] eb d7 [2] f7 d0 [2] eb ff }

  condition:
    any of them
}