rule TTP_XOR_QUAD_CurrentVersionRun_f915 {
  strings:
    $key_f915 = { aa 7a [2] 8e 74 [2] a5 58 [2] 8b 7a [2] 9f 61 [2] 90 7b [2] 8e 66 [2] 8c 67 [2] 97 61 [2] 8b 66 [2] 97 49 }

  condition:
    any of them
}