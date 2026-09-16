rule TTP_XOR_QUAD_CurrentVersionRun_e24b {
  strings:
    $key_e24b = { b1 24 [2] 95 2a [2] be 06 [2] 90 24 [2] 84 3f [2] 8b 25 [2] 95 38 [2] 97 39 [2] 8c 3f [2] 90 38 [2] 8c 17 }

  condition:
    any of them
}