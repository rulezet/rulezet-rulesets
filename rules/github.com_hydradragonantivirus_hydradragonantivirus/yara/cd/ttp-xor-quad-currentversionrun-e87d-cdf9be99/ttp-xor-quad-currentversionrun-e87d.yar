rule TTP_XOR_QUAD_CurrentVersionRun_e87d {
  strings:
    $key_e87d = { bb 12 [2] 9f 1c [2] b4 30 [2] 9a 12 [2] 8e 09 [2] 81 13 [2] 9f 0e [2] 9d 0f [2] 86 09 [2] 9a 0e [2] 86 21 }

  condition:
    any of them
}