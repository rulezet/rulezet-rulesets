rule TTP_XOR_QUAD_CurrentVersionRun_4aec {
  strings:
    $key_4aec = { 19 83 [2] 3d 8d [2] 16 a1 [2] 38 83 [2] 2c 98 [2] 23 82 [2] 3d 9f [2] 3f 9e [2] 24 98 [2] 38 9f [2] 24 b0 }

  condition:
    any of them
}