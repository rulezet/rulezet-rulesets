rule TTP_XOR_QUAD_CurrentVersionRun_0816 {
  strings:
    $key_0816 = { 5b 79 [2] 7f 77 [2] 54 5b [2] 7a 79 [2] 6e 62 [2] 61 78 [2] 7f 65 [2] 7d 64 [2] 66 62 [2] 7a 65 [2] 66 4a }

  condition:
    any of them
}