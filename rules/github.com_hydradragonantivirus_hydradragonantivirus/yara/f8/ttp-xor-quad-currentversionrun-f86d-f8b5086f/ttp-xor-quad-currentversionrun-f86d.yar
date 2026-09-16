rule TTP_XOR_QUAD_CurrentVersionRun_f86d {
  strings:
    $key_f86d = { ab 02 [2] 8f 0c [2] a4 20 [2] 8a 02 [2] 9e 19 [2] 91 03 [2] 8f 1e [2] 8d 1f [2] 96 19 [2] 8a 1e [2] 96 31 }

  condition:
    any of them
}