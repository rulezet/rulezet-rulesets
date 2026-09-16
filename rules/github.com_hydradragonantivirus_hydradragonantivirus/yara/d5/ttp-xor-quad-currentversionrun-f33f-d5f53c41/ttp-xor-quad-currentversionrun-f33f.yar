rule TTP_XOR_QUAD_CurrentVersionRun_f33f {
  strings:
    $key_f33f = { a0 50 [2] 84 5e [2] af 72 [2] 81 50 [2] 95 4b [2] 9a 51 [2] 84 4c [2] 86 4d [2] 9d 4b [2] 81 4c [2] 9d 63 }

  condition:
    any of them
}