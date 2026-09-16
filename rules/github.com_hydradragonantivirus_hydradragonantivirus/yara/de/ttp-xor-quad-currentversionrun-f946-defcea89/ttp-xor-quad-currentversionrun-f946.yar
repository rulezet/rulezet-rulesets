rule TTP_XOR_QUAD_CurrentVersionRun_f946 {
  strings:
    $key_f946 = { aa 29 [2] 8e 27 [2] a5 0b [2] 8b 29 [2] 9f 32 [2] 90 28 [2] 8e 35 [2] 8c 34 [2] 97 32 [2] 8b 35 [2] 97 1a }

  condition:
    any of them
}