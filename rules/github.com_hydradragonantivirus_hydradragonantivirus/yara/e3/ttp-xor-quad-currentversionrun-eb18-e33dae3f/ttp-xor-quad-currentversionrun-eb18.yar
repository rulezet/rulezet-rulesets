rule TTP_XOR_QUAD_CurrentVersionRun_eb18 {
  strings:
    $key_eb18 = { b8 77 [2] 9c 79 [2] b7 55 [2] 99 77 [2] 8d 6c [2] 82 76 [2] 9c 6b [2] 9e 6a [2] 85 6c [2] 99 6b [2] 85 44 }

  condition:
    any of them
}