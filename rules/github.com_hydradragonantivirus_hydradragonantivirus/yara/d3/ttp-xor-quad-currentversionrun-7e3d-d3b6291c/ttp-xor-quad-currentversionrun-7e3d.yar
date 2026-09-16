rule TTP_XOR_QUAD_CurrentVersionRun_7e3d {
  strings:
    $key_7e3d = { 2d 52 [2] 09 5c [2] 22 70 [2] 0c 52 [2] 18 49 [2] 17 53 [2] 09 4e [2] 0b 4f [2] 10 49 [2] 0c 4e [2] 10 61 }

  condition:
    any of them
}