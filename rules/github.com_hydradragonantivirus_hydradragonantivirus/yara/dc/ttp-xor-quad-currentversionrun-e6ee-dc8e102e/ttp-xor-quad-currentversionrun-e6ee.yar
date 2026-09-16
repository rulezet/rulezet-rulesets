rule TTP_XOR_QUAD_CurrentVersionRun_e6ee {
  strings:
    $key_e6ee = { b5 81 [2] 91 8f [2] ba a3 [2] 94 81 [2] 80 9a [2] 8f 80 [2] 91 9d [2] 93 9c [2] 88 9a [2] 94 9d [2] 88 b2 }

  condition:
    any of them
}