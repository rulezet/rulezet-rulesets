rule TTP_XOR_QUAD_CurrentVersionRun_5a3d {
  strings:
    $key_5a3d = { 09 52 [2] 2d 5c [2] 06 70 [2] 28 52 [2] 3c 49 [2] 33 53 [2] 2d 4e [2] 2f 4f [2] 34 49 [2] 28 4e [2] 34 61 }

  condition:
    any of them
}