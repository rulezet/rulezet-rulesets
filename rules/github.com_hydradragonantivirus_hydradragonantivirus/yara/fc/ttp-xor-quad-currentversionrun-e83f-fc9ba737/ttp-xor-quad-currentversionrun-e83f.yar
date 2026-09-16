rule TTP_XOR_QUAD_CurrentVersionRun_e83f {
  strings:
    $key_e83f = { bb 50 [2] 9f 5e [2] b4 72 [2] 9a 50 [2] 8e 4b [2] 81 51 [2] 9f 4c [2] 9d 4d [2] 86 4b [2] 9a 4c [2] 86 63 }

  condition:
    any of them
}