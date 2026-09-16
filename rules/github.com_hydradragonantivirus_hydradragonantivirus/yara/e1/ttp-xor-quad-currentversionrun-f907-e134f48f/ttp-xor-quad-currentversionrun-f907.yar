rule TTP_XOR_QUAD_CurrentVersionRun_f907 {
  strings:
    $key_f907 = { aa 68 [2] 8e 66 [2] a5 4a [2] 8b 68 [2] 9f 73 [2] 90 69 [2] 8e 74 [2] 8c 75 [2] 97 73 [2] 8b 74 [2] 97 5b }

  condition:
    any of them
}