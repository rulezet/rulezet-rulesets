rule TTP_XOR_QUAD_CurrentVersionRun_e856 {
  strings:
    $key_e856 = { bb 39 [2] 9f 37 [2] b4 1b [2] 9a 39 [2] 8e 22 [2] 81 38 [2] 9f 25 [2] 9d 24 [2] 86 22 [2] 9a 25 [2] 86 0a }

  condition:
    any of them
}