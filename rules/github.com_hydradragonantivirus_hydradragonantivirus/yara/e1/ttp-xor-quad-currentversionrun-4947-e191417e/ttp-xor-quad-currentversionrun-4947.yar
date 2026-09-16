rule TTP_XOR_QUAD_CurrentVersionRun_4947 {
  strings:
    $key_4947 = { 1a 28 [2] 3e 26 [2] 15 0a [2] 3b 28 [2] 2f 33 [2] 20 29 [2] 3e 34 [2] 3c 35 [2] 27 33 [2] 3b 34 [2] 27 1b }

  condition:
    any of them
}