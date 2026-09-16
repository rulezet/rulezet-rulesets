rule TTP_XOR_QUAD_CurrentVersionRun_e275 {
  strings:
    $key_e275 = { b1 1a [2] 95 14 [2] be 38 [2] 90 1a [2] 84 01 [2] 8b 1b [2] 95 06 [2] 97 07 [2] 8c 01 [2] 90 06 [2] 8c 29 }

  condition:
    any of them
}