rule TTP_XOR_QUAD_CurrentVersionRun_ef41 {
  strings:
    $key_ef41 = { bc 2e [2] 98 20 [2] b3 0c [2] 9d 2e [2] 89 35 [2] 86 2f [2] 98 32 [2] 9a 33 [2] 81 35 [2] 9d 32 [2] 81 1d }

  condition:
    any of them
}