rule TTP_XOR_QUAD_CurrentVersionRun_132b {
  strings:
    $key_132b = { 40 44 [2] 64 4a [2] 4f 66 [2] 61 44 [2] 75 5f [2] 7a 45 [2] 64 58 [2] 66 59 [2] 7d 5f [2] 61 58 [2] 7d 77 }

  condition:
    any of them
}