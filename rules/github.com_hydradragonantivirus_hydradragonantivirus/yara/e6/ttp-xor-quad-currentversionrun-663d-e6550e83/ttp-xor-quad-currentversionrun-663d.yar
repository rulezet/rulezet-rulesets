rule TTP_XOR_QUAD_CurrentVersionRun_663d {
  strings:
    $key_663d = { 35 52 [2] 11 5c [2] 3a 70 [2] 14 52 [2] 00 49 [2] 0f 53 [2] 11 4e [2] 13 4f [2] 08 49 [2] 14 4e [2] 08 61 }

  condition:
    any of them
}