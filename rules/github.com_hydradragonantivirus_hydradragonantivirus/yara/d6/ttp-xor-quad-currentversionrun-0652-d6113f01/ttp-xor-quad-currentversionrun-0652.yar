rule TTP_XOR_QUAD_CurrentVersionRun_0652 {
  strings:
    $key_0652 = { 55 3d [2] 71 33 [2] 5a 1f [2] 74 3d [2] 60 26 [2] 6f 3c [2] 71 21 [2] 73 20 [2] 68 26 [2] 74 21 [2] 68 0e }

  condition:
    any of them
}