rule TTP_XOR_QUAD_CurrentVersionRun_e82d {
  strings:
    $key_e82d = { bb 42 [2] 9f 4c [2] b4 60 [2] 9a 42 [2] 8e 59 [2] 81 43 [2] 9f 5e [2] 9d 5f [2] 86 59 [2] 9a 5e [2] 86 71 }

  condition:
    any of them
}