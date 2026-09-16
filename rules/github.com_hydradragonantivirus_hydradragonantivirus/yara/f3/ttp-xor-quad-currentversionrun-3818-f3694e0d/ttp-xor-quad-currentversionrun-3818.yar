rule TTP_XOR_QUAD_CurrentVersionRun_3818 {
  strings:
    $key_3818 = { 6b 77 [2] 4f 79 [2] 64 55 [2] 4a 77 [2] 5e 6c [2] 51 76 [2] 4f 6b [2] 4d 6a [2] 56 6c [2] 4a 6b [2] 56 44 }

  condition:
    any of them
}