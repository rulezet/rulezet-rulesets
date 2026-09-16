rule TTP_XOR_QUAD_CurrentVersionRun_f310 {
  strings:
    $key_f310 = { a0 7f [2] 84 71 [2] af 5d [2] 81 7f [2] 95 64 [2] 9a 7e [2] 84 63 [2] 86 62 [2] 9d 64 [2] 81 63 [2] 9d 4c }

  condition:
    any of them
}