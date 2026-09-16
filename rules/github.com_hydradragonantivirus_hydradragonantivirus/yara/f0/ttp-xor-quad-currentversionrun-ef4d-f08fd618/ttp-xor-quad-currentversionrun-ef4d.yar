rule TTP_XOR_QUAD_CurrentVersionRun_ef4d {
  strings:
    $key_ef4d = { bc 22 [2] 98 2c [2] b3 00 [2] 9d 22 [2] 89 39 [2] 86 23 [2] 98 3e [2] 9a 3f [2] 81 39 [2] 9d 3e [2] 81 11 }

  condition:
    any of them
}