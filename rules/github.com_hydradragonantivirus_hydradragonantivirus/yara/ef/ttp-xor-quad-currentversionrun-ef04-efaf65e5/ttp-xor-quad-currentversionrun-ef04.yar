rule TTP_XOR_QUAD_CurrentVersionRun_ef04 {
  strings:
    $key_ef04 = { bc 6b [2] 98 65 [2] b3 49 [2] 9d 6b [2] 89 70 [2] 86 6a [2] 98 77 [2] 9a 76 [2] 81 70 [2] 9d 77 [2] 81 58 }

  condition:
    any of them
}