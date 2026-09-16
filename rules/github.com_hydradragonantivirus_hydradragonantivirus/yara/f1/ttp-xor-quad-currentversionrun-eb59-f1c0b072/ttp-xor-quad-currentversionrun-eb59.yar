rule TTP_XOR_QUAD_CurrentVersionRun_eb59 {
  strings:
    $key_eb59 = { b8 36 [2] 9c 38 [2] b7 14 [2] 99 36 [2] 8d 2d [2] 82 37 [2] 9c 2a [2] 9e 2b [2] 85 2d [2] 99 2a [2] 85 05 }

  condition:
    any of them
}