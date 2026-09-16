rule TTP_XOR_QUAD_CurrentVersionRun_e85c {
  strings:
    $key_e85c = { bb 33 [2] 9f 3d [2] b4 11 [2] 9a 33 [2] 8e 28 [2] 81 32 [2] 9f 2f [2] 9d 2e [2] 86 28 [2] 9a 2f [2] 86 00 }

  condition:
    any of them
}