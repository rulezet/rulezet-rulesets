rule TTP_XOR_QUAD_CurrentVersionRun_e1ef {
  strings:
    $key_e1ef = { b2 80 [2] 96 8e [2] bd a2 [2] 93 80 [2] 87 9b [2] 88 81 [2] 96 9c [2] 94 9d [2] 8f 9b [2] 93 9c [2] 8f b3 }

  condition:
    any of them
}