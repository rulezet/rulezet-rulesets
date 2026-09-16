rule TTP_XOR_QUAD_CurrentVersionRun_764f {
  strings:
    $key_764f = { 25 20 [2] 01 2e [2] 2a 02 [2] 04 20 [2] 10 3b [2] 1f 21 [2] 01 3c [2] 03 3d [2] 18 3b [2] 04 3c [2] 18 13 }

  condition:
    any of them
}