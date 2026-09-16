rule TTP_XOR_QUAD_CurrentVersionRun_7111 {
  strings:
    $key_7111 = { 22 7e [2] 06 70 [2] 2d 5c [2] 03 7e [2] 17 65 [2] 18 7f [2] 06 62 [2] 04 63 [2] 1f 65 [2] 03 62 [2] 1f 4d }

  condition:
    any of them
}