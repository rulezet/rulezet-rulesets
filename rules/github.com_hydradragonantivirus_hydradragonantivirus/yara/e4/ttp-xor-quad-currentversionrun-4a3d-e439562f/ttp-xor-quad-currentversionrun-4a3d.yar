rule TTP_XOR_QUAD_CurrentVersionRun_4a3d {
  strings:
    $key_4a3d = { 19 52 [2] 3d 5c [2] 16 70 [2] 38 52 [2] 2c 49 [2] 23 53 [2] 3d 4e [2] 3f 4f [2] 24 49 [2] 38 4e [2] 24 61 }

  condition:
    any of them
}