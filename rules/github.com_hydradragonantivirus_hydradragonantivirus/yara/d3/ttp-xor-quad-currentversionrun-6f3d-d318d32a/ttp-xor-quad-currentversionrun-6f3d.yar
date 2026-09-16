rule TTP_XOR_QUAD_CurrentVersionRun_6f3d {
  strings:
    $key_6f3d = { 3c 52 [2] 18 5c [2] 33 70 [2] 1d 52 [2] 09 49 [2] 06 53 [2] 18 4e [2] 1a 4f [2] 01 49 [2] 1d 4e [2] 01 61 }

  condition:
    any of them
}