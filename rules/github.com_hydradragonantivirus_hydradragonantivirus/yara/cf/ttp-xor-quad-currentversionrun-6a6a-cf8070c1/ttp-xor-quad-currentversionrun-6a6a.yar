rule TTP_XOR_QUAD_CurrentVersionRun_6a6a {
  strings:
    $key_6a6a = { 39 05 [2] 1d 0b [2] 36 27 [2] 18 05 [2] 0c 1e [2] 03 04 [2] 1d 19 [2] 1f 18 [2] 04 1e [2] 18 19 [2] 04 36 }

  condition:
    any of them
}