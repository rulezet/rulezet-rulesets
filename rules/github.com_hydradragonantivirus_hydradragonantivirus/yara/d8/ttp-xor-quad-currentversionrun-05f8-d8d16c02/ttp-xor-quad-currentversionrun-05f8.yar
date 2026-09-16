rule TTP_XOR_QUAD_CurrentVersionRun_05f8 {
  strings:
    $key_05f8 = { 56 97 [2] 72 99 [2] 59 b5 [2] 77 97 [2] 63 8c [2] 6c 96 [2] 72 8b [2] 70 8a [2] 6b 8c [2] 77 8b [2] 6b a4 }

  condition:
    any of them
}