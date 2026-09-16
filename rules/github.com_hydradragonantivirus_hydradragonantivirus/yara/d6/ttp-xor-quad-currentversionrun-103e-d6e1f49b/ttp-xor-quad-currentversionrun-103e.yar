rule TTP_XOR_QUAD_CurrentVersionRun_103e {
  strings:
    $key_103e = { 43 51 [2] 67 5f [2] 4c 73 [2] 62 51 [2] 76 4a [2] 79 50 [2] 67 4d [2] 65 4c [2] 7e 4a [2] 62 4d [2] 7e 62 }

  condition:
    any of them
}