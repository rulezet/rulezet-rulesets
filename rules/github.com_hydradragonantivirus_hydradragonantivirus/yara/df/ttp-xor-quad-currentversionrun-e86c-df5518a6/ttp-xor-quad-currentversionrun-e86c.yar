rule TTP_XOR_QUAD_CurrentVersionRun_e86c {
  strings:
    $key_e86c = { bb 03 [2] 9f 0d [2] b4 21 [2] 9a 03 [2] 8e 18 [2] 81 02 [2] 9f 1f [2] 9d 1e [2] 86 18 [2] 9a 1f [2] 86 30 }

  condition:
    any of them
}