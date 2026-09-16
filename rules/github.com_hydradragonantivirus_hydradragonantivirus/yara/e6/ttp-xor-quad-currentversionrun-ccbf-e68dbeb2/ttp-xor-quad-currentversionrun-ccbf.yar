rule TTP_XOR_QUAD_CurrentVersionRun_ccbf {
  strings:
    $key_ccbf = { 9f d0 [2] bb de [2] 90 f2 [2] be d0 [2] aa cb [2] a5 d1 [2] bb cc [2] b9 cd [2] a2 cb [2] be cc [2] a2 e3 }

  condition:
    any of them
}