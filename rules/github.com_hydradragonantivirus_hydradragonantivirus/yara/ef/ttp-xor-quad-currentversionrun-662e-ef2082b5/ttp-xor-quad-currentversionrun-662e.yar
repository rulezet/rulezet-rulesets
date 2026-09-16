rule TTP_XOR_QUAD_CurrentVersionRun_662e {
  strings:
    $key_662e = { 35 41 [2] 11 4f [2] 3a 63 [2] 14 41 [2] 00 5a [2] 0f 40 [2] 11 5d [2] 13 5c [2] 08 5a [2] 14 5d [2] 08 72 }

  condition:
    any of them
}