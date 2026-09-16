rule TTP_XOR_QUAD_CurrentVersionRun_ea19 {
  strings:
    $key_ea19 = { b9 76 [2] 9d 78 [2] b6 54 [2] 98 76 [2] 8c 6d [2] 83 77 [2] 9d 6a [2] 9f 6b [2] 84 6d [2] 98 6a [2] 84 45 }

  condition:
    any of them
}