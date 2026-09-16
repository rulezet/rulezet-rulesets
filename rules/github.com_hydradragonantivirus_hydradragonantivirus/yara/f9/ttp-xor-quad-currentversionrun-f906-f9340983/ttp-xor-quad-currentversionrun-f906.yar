rule TTP_XOR_QUAD_CurrentVersionRun_f906 {
  strings:
    $key_f906 = { aa 69 [2] 8e 67 [2] a5 4b [2] 8b 69 [2] 9f 72 [2] 90 68 [2] 8e 75 [2] 8c 74 [2] 97 72 [2] 8b 75 [2] 97 5a }

  condition:
    any of them
}