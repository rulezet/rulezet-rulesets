rule TTP_XOR_QUAD_CurrentVersionRun_6c71 {
  strings:
    $key_6c71 = { 3f 1e [2] 1b 10 [2] 30 3c [2] 1e 1e [2] 0a 05 [2] 05 1f [2] 1b 02 [2] 19 03 [2] 02 05 [2] 1e 02 [2] 02 2d }

  condition:
    any of them
}