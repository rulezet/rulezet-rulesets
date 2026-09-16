rule TTP_XOR_QUAD_CurrentVersionRun_f34d {
  strings:
    $key_f34d = { a0 22 [2] 84 2c [2] af 00 [2] 81 22 [2] 95 39 [2] 9a 23 [2] 84 3e [2] 86 3f [2] 9d 39 [2] 81 3e [2] 9d 11 }

  condition:
    any of them
}