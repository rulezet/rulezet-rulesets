rule TTP_XOR_QUAD_CurrentVersionRun_f94b {
  strings:
    $key_f94b = { aa 24 [2] 8e 2a [2] a5 06 [2] 8b 24 [2] 9f 3f [2] 90 25 [2] 8e 38 [2] 8c 39 [2] 97 3f [2] 8b 38 [2] 97 17 }

  condition:
    any of them
}