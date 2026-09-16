rule TTP_XOR_QUAD_CurrentVersionRun_542c {
  strings:
    $key_542c = { 07 43 [2] 23 4d [2] 08 61 [2] 26 43 [2] 32 58 [2] 3d 42 [2] 23 5f [2] 21 5e [2] 3a 58 [2] 26 5f [2] 3a 70 }

  condition:
    any of them
}