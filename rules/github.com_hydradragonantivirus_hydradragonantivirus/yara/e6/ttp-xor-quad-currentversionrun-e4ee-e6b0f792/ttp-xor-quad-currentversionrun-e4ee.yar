rule TTP_XOR_QUAD_CurrentVersionRun_e4ee {
  strings:
    $key_e4ee = { b7 81 [2] 93 8f [2] b8 a3 [2] 96 81 [2] 82 9a [2] 8d 80 [2] 93 9d [2] 91 9c [2] 8a 9a [2] 96 9d [2] 8a b2 }

  condition:
    any of them
}