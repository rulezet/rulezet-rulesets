rule TTP_XOR_QUAD_CurrentVersionRun_e1ee {
  strings:
    $key_e1ee = { b2 81 [2] 96 8f [2] bd a3 [2] 93 81 [2] 87 9a [2] 88 80 [2] 96 9d [2] 94 9c [2] 8f 9a [2] 93 9d [2] 8f b2 }

  condition:
    any of them
}