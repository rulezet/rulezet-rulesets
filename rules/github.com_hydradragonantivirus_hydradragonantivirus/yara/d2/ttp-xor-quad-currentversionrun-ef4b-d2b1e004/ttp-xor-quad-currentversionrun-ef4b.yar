rule TTP_XOR_QUAD_CurrentVersionRun_ef4b {
  strings:
    $key_ef4b = { bc 24 [2] 98 2a [2] b3 06 [2] 9d 24 [2] 89 3f [2] 86 25 [2] 98 38 [2] 9a 39 [2] 81 3f [2] 9d 38 [2] 81 17 }

  condition:
    any of them
}