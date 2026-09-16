rule TTP_XOR_QUAD_CurrentVersionRun_ef78 {
  strings:
    $key_ef78 = { bc 17 [2] 98 19 [2] b3 35 [2] 9d 17 [2] 89 0c [2] 86 16 [2] 98 0b [2] 9a 0a [2] 81 0c [2] 9d 0b [2] 81 24 }

  condition:
    any of them
}