rule TTP_XOR_QUAD_CurrentVersionRun_e801 {
  strings:
    $key_e801 = { bb 6e [2] 9f 60 [2] b4 4c [2] 9a 6e [2] 8e 75 [2] 81 6f [2] 9f 72 [2] 9d 73 [2] 86 75 [2] 9a 72 [2] 86 5d }

  condition:
    any of them
}