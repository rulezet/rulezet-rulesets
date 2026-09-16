rule TTP_XOR_QUAD_CurrentVersionRun_f966 {
  strings:
    $key_f966 = { aa 09 [2] 8e 07 [2] a5 2b [2] 8b 09 [2] 9f 12 [2] 90 08 [2] 8e 15 [2] 8c 14 [2] 97 12 [2] 8b 15 [2] 97 3a }

  condition:
    any of them
}