rule TTP_XOR_QUAD_CurrentVersionRun_7e6d {
  strings:
    $key_7e6d = { 2d 02 [2] 09 0c [2] 22 20 [2] 0c 02 [2] 18 19 [2] 17 03 [2] 09 1e [2] 0b 1f [2] 10 19 [2] 0c 1e [2] 10 31 }

  condition:
    any of them
}