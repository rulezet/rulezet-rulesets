rule TTP_XOR_QUAD_CurrentVersionRun_f963 {
  strings:
    $key_f963 = { aa 0c [2] 8e 02 [2] a5 2e [2] 8b 0c [2] 9f 17 [2] 90 0d [2] 8e 10 [2] 8c 11 [2] 97 17 [2] 8b 10 [2] 97 3f }

  condition:
    any of them
}