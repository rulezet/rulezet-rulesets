rule TTP_XOR_QUAD_CurrentVersionRun_6a72 {
  strings:
    $key_6a72 = { 39 1d [2] 1d 13 [2] 36 3f [2] 18 1d [2] 0c 06 [2] 03 1c [2] 1d 01 [2] 1f 00 [2] 04 06 [2] 18 01 [2] 04 2e }

  condition:
    any of them
}