rule TTP_XOR_QUAD_CurrentVersionRun_ea18 {
  strings:
    $key_ea18 = { b9 77 [2] 9d 79 [2] b6 55 [2] 98 77 [2] 8c 6c [2] 83 76 [2] 9d 6b [2] 9f 6a [2] 84 6c [2] 98 6b [2] 84 44 }

  condition:
    any of them
}