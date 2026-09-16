rule TTP_XOR_QUAD_CurrentVersionRun_ef36 {
  strings:
    $key_ef36 = { bc 59 [2] 98 57 [2] b3 7b [2] 9d 59 [2] 89 42 [2] 86 58 [2] 98 45 [2] 9a 44 [2] 81 42 [2] 9d 45 [2] 81 6a }

  condition:
    any of them
}