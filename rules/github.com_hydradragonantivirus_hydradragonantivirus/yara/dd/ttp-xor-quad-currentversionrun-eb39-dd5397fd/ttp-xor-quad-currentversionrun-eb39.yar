rule TTP_XOR_QUAD_CurrentVersionRun_eb39 {
  strings:
    $key_eb39 = { b8 56 [2] 9c 58 [2] b7 74 [2] 99 56 [2] 8d 4d [2] 82 57 [2] 9c 4a [2] 9e 4b [2] 85 4d [2] 99 4a [2] 85 65 }

  condition:
    any of them
}