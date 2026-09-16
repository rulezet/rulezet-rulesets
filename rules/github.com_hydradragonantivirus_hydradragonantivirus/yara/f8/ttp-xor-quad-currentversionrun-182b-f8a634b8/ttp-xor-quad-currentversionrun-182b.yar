rule TTP_XOR_QUAD_CurrentVersionRun_182b {
  strings:
    $key_182b = { 4b 44 [2] 6f 4a [2] 44 66 [2] 6a 44 [2] 7e 5f [2] 71 45 [2] 6f 58 [2] 6d 59 [2] 76 5f [2] 6a 58 [2] 76 77 }

  condition:
    any of them
}