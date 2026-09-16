rule TTP_XOR_QUAD_CurrentVersionRun_6a7c {
  strings:
    $key_6a7c = { 39 13 [2] 1d 1d [2] 36 31 [2] 18 13 [2] 0c 08 [2] 03 12 [2] 1d 0f [2] 1f 0e [2] 04 08 [2] 18 0f [2] 04 20 }

  condition:
    any of them
}