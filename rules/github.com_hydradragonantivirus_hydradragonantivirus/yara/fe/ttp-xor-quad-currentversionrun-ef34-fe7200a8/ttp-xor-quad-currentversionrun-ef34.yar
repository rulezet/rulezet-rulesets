rule TTP_XOR_QUAD_CurrentVersionRun_ef34 {
  strings:
    $key_ef34 = { bc 5b [2] 98 55 [2] b3 79 [2] 9d 5b [2] 89 40 [2] 86 5a [2] 98 47 [2] 9a 46 [2] 81 40 [2] 9d 47 [2] 81 68 }

  condition:
    any of them
}