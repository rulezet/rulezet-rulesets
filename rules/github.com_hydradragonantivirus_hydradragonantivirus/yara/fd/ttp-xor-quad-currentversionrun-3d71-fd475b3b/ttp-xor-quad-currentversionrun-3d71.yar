rule TTP_XOR_QUAD_CurrentVersionRun_3d71 {
  strings:
    $key_3d71 = { 6e 1e [2] 4a 10 [2] 61 3c [2] 4f 1e [2] 5b 05 [2] 54 1f [2] 4a 02 [2] 48 03 [2] 53 05 [2] 4f 02 [2] 53 2d }

  condition:
    any of them
}