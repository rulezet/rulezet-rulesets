rule TTP_XOR_QUAD_CurrentVersionRun_ef31 {
  strings:
    $key_ef31 = { bc 5e [2] 98 50 [2] b3 7c [2] 9d 5e [2] 89 45 [2] 86 5f [2] 98 42 [2] 9a 43 [2] 81 45 [2] 9d 42 [2] 81 6d }

  condition:
    any of them
}