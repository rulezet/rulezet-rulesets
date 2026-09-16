rule TTP_XOR_QUAD_CurrentVersionRun_ef39 {
  strings:
    $key_ef39 = { bc 56 [2] 98 58 [2] b3 74 [2] 9d 56 [2] 89 4d [2] 86 57 [2] 98 4a [2] 9a 4b [2] 81 4d [2] 9d 4a [2] 81 65 }

  condition:
    any of them
}