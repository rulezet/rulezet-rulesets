rule TTP_XOR_QUAD_CurrentVersionRun_4e6d {
  strings:
    $key_4e6d = { 1d 02 [2] 39 0c [2] 12 20 [2] 3c 02 [2] 28 19 [2] 27 03 [2] 39 1e [2] 3b 1f [2] 20 19 [2] 3c 1e [2] 20 31 }

  condition:
    any of them
}