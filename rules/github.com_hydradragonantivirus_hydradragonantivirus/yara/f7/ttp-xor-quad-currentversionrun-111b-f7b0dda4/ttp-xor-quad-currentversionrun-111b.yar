rule TTP_XOR_QUAD_CurrentVersionRun_111b {
  strings:
    $key_111b = { 42 74 [2] 66 7a [2] 4d 56 [2] 63 74 [2] 77 6f [2] 78 75 [2] 66 68 [2] 64 69 [2] 7f 6f [2] 63 68 [2] 7f 47 }

  condition:
    any of them
}