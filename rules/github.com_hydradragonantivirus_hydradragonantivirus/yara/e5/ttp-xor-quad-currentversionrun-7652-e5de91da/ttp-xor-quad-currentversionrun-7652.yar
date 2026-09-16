rule TTP_XOR_QUAD_CurrentVersionRun_7652 {
  strings:
    $key_7652 = { 25 3d [2] 01 33 [2] 2a 1f [2] 04 3d [2] 10 26 [2] 1f 3c [2] 01 21 [2] 03 20 [2] 18 26 [2] 04 21 [2] 18 0e }

  condition:
    any of them
}