rule TTP_XOR_QUAD_CurrentVersionRun_ef54 {
  strings:
    $key_ef54 = { bc 3b [2] 98 35 [2] b3 19 [2] 9d 3b [2] 89 20 [2] 86 3a [2] 98 27 [2] 9a 26 [2] 81 20 [2] 9d 27 [2] 81 08 }

  condition:
    any of them
}