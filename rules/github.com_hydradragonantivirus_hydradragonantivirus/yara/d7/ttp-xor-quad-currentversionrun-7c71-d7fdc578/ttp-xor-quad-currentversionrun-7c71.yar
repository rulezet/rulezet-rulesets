rule TTP_XOR_QUAD_CurrentVersionRun_7c71 {
  strings:
    $key_7c71 = { 2f 1e [2] 0b 10 [2] 20 3c [2] 0e 1e [2] 1a 05 [2] 15 1f [2] 0b 02 [2] 09 03 [2] 12 05 [2] 0e 02 [2] 12 2d }

  condition:
    any of them
}