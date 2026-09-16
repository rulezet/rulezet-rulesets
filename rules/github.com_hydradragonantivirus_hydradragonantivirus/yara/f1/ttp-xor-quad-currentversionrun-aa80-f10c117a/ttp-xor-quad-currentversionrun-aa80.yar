rule TTP_XOR_QUAD_CurrentVersionRun_aa80 {
  strings:
    $key_aa80 = { f9 ef [2] dd e1 [2] f6 cd [2] d8 ef [2] cc f4 [2] c3 ee [2] dd f3 [2] df f2 [2] c4 f4 [2] d8 f3 [2] c4 dc }

  condition:
    any of them
}