rule TTP_XOR_QUAD_CurrentVersionRun_6b1d {
  strings:
    $key_6b1d = { 38 72 [2] 1c 7c [2] 37 50 [2] 19 72 [2] 0d 69 [2] 02 73 [2] 1c 6e [2] 1e 6f [2] 05 69 [2] 19 6e [2] 05 41 }

  condition:
    any of them
}