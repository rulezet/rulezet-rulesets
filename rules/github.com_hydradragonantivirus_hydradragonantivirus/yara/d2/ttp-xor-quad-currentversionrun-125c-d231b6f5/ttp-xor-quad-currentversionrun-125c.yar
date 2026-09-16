rule TTP_XOR_QUAD_CurrentVersionRun_125c {
  strings:
    $key_125c = { 41 33 [2] 65 3d [2] 4e 11 [2] 60 33 [2] 74 28 [2] 7b 32 [2] 65 2f [2] 67 2e [2] 7c 28 [2] 60 2f [2] 7c 00 }

  condition:
    any of them
}