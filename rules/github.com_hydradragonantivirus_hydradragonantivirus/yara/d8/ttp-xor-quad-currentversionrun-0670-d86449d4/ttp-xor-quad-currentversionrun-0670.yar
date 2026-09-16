rule TTP_XOR_QUAD_CurrentVersionRun_0670 {
  strings:
    $key_0670 = { 55 1f [2] 71 11 [2] 5a 3d [2] 74 1f [2] 60 04 [2] 6f 1e [2] 71 03 [2] 73 02 [2] 68 04 [2] 74 03 [2] 68 2c }

  condition:
    any of them
}