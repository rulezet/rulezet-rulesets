rule TTP_XOR_QUAD_CurrentVersionRun_b0ee {
  strings:
    $key_b0ee = { e3 81 [2] c7 8f [2] ec a3 [2] c2 81 [2] d6 9a [2] d9 80 [2] c7 9d [2] c5 9c [2] de 9a [2] c2 9d [2] de b2 }

  condition:
    any of them
}