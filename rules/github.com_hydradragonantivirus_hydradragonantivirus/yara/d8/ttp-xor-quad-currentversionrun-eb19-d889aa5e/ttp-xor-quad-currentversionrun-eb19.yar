rule TTP_XOR_QUAD_CurrentVersionRun_eb19 {
  strings:
    $key_eb19 = { b8 76 [2] 9c 78 [2] b7 54 [2] 99 76 [2] 8d 6d [2] 82 77 [2] 9c 6a [2] 9e 6b [2] 85 6d [2] 99 6a [2] 85 45 }

  condition:
    any of them
}