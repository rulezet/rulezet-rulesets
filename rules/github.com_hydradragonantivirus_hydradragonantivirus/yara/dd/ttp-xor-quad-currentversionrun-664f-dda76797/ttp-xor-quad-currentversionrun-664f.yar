rule TTP_XOR_QUAD_CurrentVersionRun_664f {
  strings:
    $key_664f = { 35 20 [2] 11 2e [2] 3a 02 [2] 14 20 [2] 00 3b [2] 0f 21 [2] 11 3c [2] 13 3d [2] 08 3b [2] 14 3c [2] 08 13 }

  condition:
    any of them
}