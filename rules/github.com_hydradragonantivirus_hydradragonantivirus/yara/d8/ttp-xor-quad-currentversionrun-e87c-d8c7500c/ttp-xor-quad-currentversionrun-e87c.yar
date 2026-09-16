rule TTP_XOR_QUAD_CurrentVersionRun_e87c {
  strings:
    $key_e87c = { bb 13 [2] 9f 1d [2] b4 31 [2] 9a 13 [2] 8e 08 [2] 81 12 [2] 9f 0f [2] 9d 0e [2] 86 08 [2] 9a 0f [2] 86 20 }

  condition:
    any of them
}