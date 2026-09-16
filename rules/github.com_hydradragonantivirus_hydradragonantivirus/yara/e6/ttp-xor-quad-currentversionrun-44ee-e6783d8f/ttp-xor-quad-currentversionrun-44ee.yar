rule TTP_XOR_QUAD_CurrentVersionRun_44ee {
  strings:
    $key_44ee = { 17 81 [2] 33 8f [2] 18 a3 [2] 36 81 [2] 22 9a [2] 2d 80 [2] 33 9d [2] 31 9c [2] 2a 9a [2] 36 9d [2] 2a b2 }

  condition:
    any of them
}