rule TTP_XOR_QUAD_CurrentVersionRun_bdbf {
  strings:
    $key_bdbf = { ee d0 [2] ca de [2] e1 f2 [2] cf d0 [2] db cb [2] d4 d1 [2] ca cc [2] c8 cd [2] d3 cb [2] cf cc [2] d3 e3 }

  condition:
    any of them
}