rule TTP_XOR_QUAD_CurrentVersionRun_f872 {
  strings:
    $key_f872 = { ab 1d [2] 8f 13 [2] a4 3f [2] 8a 1d [2] 9e 06 [2] 91 1c [2] 8f 01 [2] 8d 00 [2] 96 06 [2] 8a 01 [2] 96 2e }

  condition:
    any of them
}