rule TTP_XOR_QUAD_CurrentVersionRun_504b {
  strings:
    $key_504b = { 03 24 [2] 27 2a [2] 0c 06 [2] 22 24 [2] 36 3f [2] 39 25 [2] 27 38 [2] 25 39 [2] 3e 3f [2] 22 38 [2] 3e 17 }

  condition:
    any of them
}