rule TTP_XOR_QUAD_CurrentVersionRun_8fbf {
  strings:
    $key_8fbf = { dc d0 [2] f8 de [2] d3 f2 [2] fd d0 [2] e9 cb [2] e6 d1 [2] f8 cc [2] fa cd [2] e1 cb [2] fd cc [2] e1 e3 }

  condition:
    any of them
}