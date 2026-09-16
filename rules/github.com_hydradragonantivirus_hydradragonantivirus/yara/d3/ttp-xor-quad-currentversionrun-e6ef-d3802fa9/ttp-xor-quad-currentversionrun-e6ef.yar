rule TTP_XOR_QUAD_CurrentVersionRun_e6ef {
  strings:
    $key_e6ef = { b5 80 [2] 91 8e [2] ba a2 [2] 94 80 [2] 80 9b [2] 8f 81 [2] 91 9c [2] 93 9d [2] 88 9b [2] 94 9c [2] 88 b3 }

  condition:
    any of them
}