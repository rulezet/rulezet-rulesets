rule TTP_XOR_QUAD_CurrentVersionRun_ef47 {
  strings:
    $key_ef47 = { bc 28 [2] 98 26 [2] b3 0a [2] 9d 28 [2] 89 33 [2] 86 29 [2] 98 34 [2] 9a 35 [2] 81 33 [2] 9d 34 [2] 81 1b }

  condition:
    any of them
}