rule TTP_XOR_QUAD_CurrentVersionRun_e25c {
  strings:
    $key_e25c = { b1 33 [2] 95 3d [2] be 11 [2] 90 33 [2] 84 28 [2] 8b 32 [2] 95 2f [2] 97 2e [2] 8c 28 [2] 90 2f [2] 8c 00 }

  condition:
    any of them
}