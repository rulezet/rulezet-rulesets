rule TTP_XOR_QUAD_CurrentVersionRun_3836 {
  strings:
    $key_3836 = { 6b 59 [2] 4f 57 [2] 64 7b [2] 4a 59 [2] 5e 42 [2] 51 58 [2] 4f 45 [2] 4d 44 [2] 56 42 [2] 4a 45 [2] 56 6a }

  condition:
    any of them
}