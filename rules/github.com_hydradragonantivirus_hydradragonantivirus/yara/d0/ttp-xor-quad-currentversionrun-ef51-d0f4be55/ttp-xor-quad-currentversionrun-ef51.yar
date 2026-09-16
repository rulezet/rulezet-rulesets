rule TTP_XOR_QUAD_CurrentVersionRun_ef51 {
  strings:
    $key_ef51 = { bc 3e [2] 98 30 [2] b3 1c [2] 9d 3e [2] 89 25 [2] 86 3f [2] 98 22 [2] 9a 23 [2] 81 25 [2] 9d 22 [2] 81 0d }

  condition:
    any of them
}