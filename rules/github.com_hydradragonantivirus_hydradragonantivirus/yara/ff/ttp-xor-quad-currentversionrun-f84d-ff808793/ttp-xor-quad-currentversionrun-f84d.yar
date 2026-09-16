rule TTP_XOR_QUAD_CurrentVersionRun_f84d {
  strings:
    $key_f84d = { ab 22 [2] 8f 2c [2] a4 00 [2] 8a 22 [2] 9e 39 [2] 91 23 [2] 8f 3e [2] 8d 3f [2] 96 39 [2] 8a 3e [2] 96 11 }

  condition:
    any of them
}