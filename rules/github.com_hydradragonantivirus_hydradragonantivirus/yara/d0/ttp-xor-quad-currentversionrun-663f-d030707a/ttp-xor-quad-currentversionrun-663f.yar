rule TTP_XOR_QUAD_CurrentVersionRun_663f {
  strings:
    $key_663f = { 35 50 [2] 11 5e [2] 3a 72 [2] 14 50 [2] 00 4b [2] 0f 51 [2] 11 4c [2] 13 4d [2] 08 4b [2] 14 4c [2] 08 63 }

  condition:
    any of them
}