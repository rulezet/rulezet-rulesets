rule TTP_XOR_QUAD_CurrentVersionRun_6a71 {
  strings:
    $key_6a71 = { 39 1e [2] 1d 10 [2] 36 3c [2] 18 1e [2] 0c 05 [2] 03 1f [2] 1d 02 [2] 1f 03 [2] 04 05 [2] 18 02 [2] 04 2d }

  condition:
    any of them
}