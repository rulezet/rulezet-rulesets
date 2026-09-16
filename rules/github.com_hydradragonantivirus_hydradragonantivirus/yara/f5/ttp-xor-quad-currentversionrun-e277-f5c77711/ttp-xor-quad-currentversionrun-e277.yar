rule TTP_XOR_QUAD_CurrentVersionRun_e277 {
  strings:
    $key_e277 = { b1 18 [2] 95 16 [2] be 3a [2] 90 18 [2] 84 03 [2] 8b 19 [2] 95 04 [2] 97 05 [2] 8c 03 [2] 90 04 [2] 8c 2b }

  condition:
    any of them
}