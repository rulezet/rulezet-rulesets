rule TTP_XOR_QUAD_CurrentVersionRun_052b {
  strings:
    $key_052b = { 56 44 [2] 72 4a [2] 59 66 [2] 77 44 [2] 63 5f [2] 6c 45 [2] 72 58 [2] 70 59 [2] 6b 5f [2] 77 58 [2] 6b 77 }

  condition:
    any of them
}