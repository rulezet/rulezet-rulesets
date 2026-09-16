rule TTP_XOR_QUAD_CurrentVersionRun_e269 {
  strings:
    $key_e269 = { b1 06 [2] 95 08 [2] be 24 [2] 90 06 [2] 84 1d [2] 8b 07 [2] 95 1a [2] 97 1b [2] 8c 1d [2] 90 1a [2] 8c 35 }

  condition:
    any of them
}