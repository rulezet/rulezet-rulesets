rule TTP_XOR_QUAD_CurrentVersionRun_0256 {
  strings:
    $key_0256 = { 51 39 [2] 75 37 [2] 5e 1b [2] 70 39 [2] 64 22 [2] 6b 38 [2] 75 25 [2] 77 24 [2] 6c 22 [2] 70 25 [2] 6c 0a }

  condition:
    any of them
}