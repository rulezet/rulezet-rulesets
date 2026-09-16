rule TTP_XOR_QUAD_CurrentVersionRun_f841 {
  strings:
    $key_f841 = { ab 2e [2] 8f 20 [2] a4 0c [2] 8a 2e [2] 9e 35 [2] 91 2f [2] 8f 32 [2] 8d 33 [2] 96 35 [2] 8a 32 [2] 96 1d }

  condition:
    any of them
}