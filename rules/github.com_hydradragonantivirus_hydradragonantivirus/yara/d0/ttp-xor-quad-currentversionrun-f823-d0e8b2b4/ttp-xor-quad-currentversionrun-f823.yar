rule TTP_XOR_QUAD_CurrentVersionRun_f823 {
  strings:
    $key_f823 = { ab 4c [2] 8f 42 [2] a4 6e [2] 8a 4c [2] 9e 57 [2] 91 4d [2] 8f 50 [2] 8d 51 [2] 96 57 [2] 8a 50 [2] 96 7f }

  condition:
    any of them
}