rule TTP_XOR_QUAD_CurrentVersionRun_ef79 {
  strings:
    $key_ef79 = { bc 16 [2] 98 18 [2] b3 34 [2] 9d 16 [2] 89 0d [2] 86 17 [2] 98 0a [2] 9a 0b [2] 81 0d [2] 9d 0a [2] 81 25 }

  condition:
    any of them
}