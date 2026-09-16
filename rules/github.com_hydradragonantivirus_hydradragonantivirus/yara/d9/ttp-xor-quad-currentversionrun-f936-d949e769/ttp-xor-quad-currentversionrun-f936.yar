rule TTP_XOR_QUAD_CurrentVersionRun_f936 {
  strings:
    $key_f936 = { aa 59 [2] 8e 57 [2] a5 7b [2] 8b 59 [2] 9f 42 [2] 90 58 [2] 8e 45 [2] 8c 44 [2] 97 42 [2] 8b 45 [2] 97 6a }

  condition:
    any of them
}