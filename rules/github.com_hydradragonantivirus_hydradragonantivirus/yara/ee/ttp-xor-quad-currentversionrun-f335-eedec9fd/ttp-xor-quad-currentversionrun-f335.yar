rule TTP_XOR_QUAD_CurrentVersionRun_f335 {
  strings:
    $key_f335 = { a0 5a [2] 84 54 [2] af 78 [2] 81 5a [2] 95 41 [2] 9a 5b [2] 84 46 [2] 86 47 [2] 9d 41 [2] 81 46 [2] 9d 69 }

  condition:
    any of them
}