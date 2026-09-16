rule TTP_XOR_QUAD_CurrentVersionRun_ef42 {
  strings:
    $key_ef42 = { bc 2d [2] 98 23 [2] b3 0f [2] 9d 2d [2] 89 36 [2] 86 2c [2] 98 31 [2] 9a 30 [2] 81 36 [2] 9d 31 [2] 81 1e }

  condition:
    any of them
}