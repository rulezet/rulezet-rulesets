rule TTP_XOR_QUAD_CurrentVersionRun_501b {
  strings:
    $key_501b = { 03 74 [2] 27 7a [2] 0c 56 [2] 22 74 [2] 36 6f [2] 39 75 [2] 27 68 [2] 25 69 [2] 3e 6f [2] 22 68 [2] 3e 47 }

  condition:
    any of them
}