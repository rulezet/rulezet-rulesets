rule TTP_XOR_QUAD_CurrentVersionRun_e256 {
  strings:
    $key_e256 = { b1 39 [2] 95 37 [2] be 1b [2] 90 39 [2] 84 22 [2] 8b 38 [2] 95 25 [2] 97 24 [2] 8c 22 [2] 90 25 [2] 8c 0a }

  condition:
    any of them
}