rule TTP_XOR_QUAD_CurrentVersionRun_192b {
  strings:
    $key_192b = { 4a 44 [2] 6e 4a [2] 45 66 [2] 6b 44 [2] 7f 5f [2] 70 45 [2] 6e 58 [2] 6c 59 [2] 77 5f [2] 6b 58 [2] 77 77 }

  condition:
    any of them
}