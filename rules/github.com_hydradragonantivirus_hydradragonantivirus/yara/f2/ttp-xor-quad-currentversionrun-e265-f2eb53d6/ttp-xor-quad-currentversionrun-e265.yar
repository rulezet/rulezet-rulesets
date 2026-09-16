rule TTP_XOR_QUAD_CurrentVersionRun_e265 {
  strings:
    $key_e265 = { b1 0a [2] 95 04 [2] be 28 [2] 90 0a [2] 84 11 [2] 8b 0b [2] 95 16 [2] 97 17 [2] 8c 11 [2] 90 16 [2] 8c 39 }

  condition:
    any of them
}