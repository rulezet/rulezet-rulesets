rule TTP_XOR_QUAD_CurrentVersionRun_f82c {
  strings:
    $key_f82c = { ab 43 [2] 8f 4d [2] a4 61 [2] 8a 43 [2] 9e 58 [2] 91 42 [2] 8f 5f [2] 8d 5e [2] 96 58 [2] 8a 5f [2] 96 70 }

  condition:
    any of them
}