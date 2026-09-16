rule TTP_XOR_QUAD_CurrentVersionRun_4a20 {
  strings:
    $key_4a20 = { 19 4f [2] 3d 41 [2] 16 6d [2] 38 4f [2] 2c 54 [2] 23 4e [2] 3d 53 [2] 3f 52 [2] 24 54 [2] 38 53 [2] 24 7c }

  condition:
    any of them
}