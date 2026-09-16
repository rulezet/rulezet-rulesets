rule TTP_XOR_QUAD_CurrentVersionRun_0a1b {
  strings:
    $key_0a1b = { 59 74 [2] 7d 7a [2] 56 56 [2] 78 74 [2] 6c 6f [2] 63 75 [2] 7d 68 [2] 7f 69 [2] 64 6f [2] 78 68 [2] 64 47 }

  condition:
    any of them
}