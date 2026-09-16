rule TTP_XOR_QUAD_CurrentVersionRun_ef23 {
  strings:
    $key_ef23 = { bc 4c [2] 98 42 [2] b3 6e [2] 9d 4c [2] 89 57 [2] 86 4d [2] 98 50 [2] 9a 51 [2] 81 57 [2] 9d 50 [2] 81 7f }

  condition:
    any of them
}