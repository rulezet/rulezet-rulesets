rule TTP_XOR_QUAD_CurrentVersionRun_4afc {
  strings:
    $key_4afc = { 19 93 [2] 3d 9d [2] 16 b1 [2] 38 93 [2] 2c 88 [2] 23 92 [2] 3d 8f [2] 3f 8e [2] 24 88 [2] 38 8f [2] 24 a0 }

  condition:
    any of them
}