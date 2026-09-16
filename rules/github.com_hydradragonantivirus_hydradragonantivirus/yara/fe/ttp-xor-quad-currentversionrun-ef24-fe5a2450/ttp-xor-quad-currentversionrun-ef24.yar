rule TTP_XOR_QUAD_CurrentVersionRun_ef24 {
  strings:
    $key_ef24 = { bc 4b [2] 98 45 [2] b3 69 [2] 9d 4b [2] 89 50 [2] 86 4a [2] 98 57 [2] 9a 56 [2] 81 50 [2] 9d 57 [2] 81 78 }

  condition:
    any of them
}