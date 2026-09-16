rule TTP_XOR_QUAD_CurrentVersionRun_eb38 {
  strings:
    $key_eb38 = { b8 57 [2] 9c 59 [2] b7 75 [2] 99 57 [2] 8d 4c [2] 82 56 [2] 9c 4b [2] 9e 4a [2] 85 4c [2] 99 4b [2] 85 64 }

  condition:
    any of them
}