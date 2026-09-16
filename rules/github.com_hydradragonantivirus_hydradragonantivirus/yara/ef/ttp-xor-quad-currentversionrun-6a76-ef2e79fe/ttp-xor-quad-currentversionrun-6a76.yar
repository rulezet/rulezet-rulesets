rule TTP_XOR_QUAD_CurrentVersionRun_6a76 {
  strings:
    $key_6a76 = { 39 19 [2] 1d 17 [2] 36 3b [2] 18 19 [2] 0c 02 [2] 03 18 [2] 1d 05 [2] 1f 04 [2] 04 02 [2] 18 05 [2] 04 2a }

  condition:
    any of them
}