rule TTP_XOR_QUAD_CurrentVersionRun_3f18 {
  strings:
    $key_3f18 = { 6c 77 [2] 48 79 [2] 63 55 [2] 4d 77 [2] 59 6c [2] 56 76 [2] 48 6b [2] 4a 6a [2] 51 6c [2] 4d 6b [2] 51 44 }

  condition:
    any of them
}