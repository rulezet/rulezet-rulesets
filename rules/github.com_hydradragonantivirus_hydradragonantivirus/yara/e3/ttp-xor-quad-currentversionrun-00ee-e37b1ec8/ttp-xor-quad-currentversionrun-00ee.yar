rule TTP_XOR_QUAD_CurrentVersionRun_00ee {
  strings:
    $key_00ee = { 53 81 [2] 77 8f [2] 5c a3 [2] 72 81 [2] 66 9a [2] 69 80 [2] 77 9d [2] 75 9c [2] 6e 9a [2] 72 9d [2] 6e b2 }

  condition:
    any of them
}