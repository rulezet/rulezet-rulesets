rule TTP_XOR_QUAD_CurrentVersionRun_3816 {
  strings:
    $key_3816 = { 6b 79 [2] 4f 77 [2] 64 5b [2] 4a 79 [2] 5e 62 [2] 51 78 [2] 4f 65 [2] 4d 64 [2] 56 62 [2] 4a 65 [2] 56 4a }

  condition:
    any of them
}