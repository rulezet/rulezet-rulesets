rule TTP_XOR_QUAD_CurrentVersionRun_ebe8 {
  strings:
    $key_ebe8 = { b8 87 [2] 9c 89 [2] b7 a5 [2] 99 87 [2] 8d 9c [2] 82 86 [2] 9c 9b [2] 9e 9a [2] 85 9c [2] 99 9b [2] 85 b4 }

  condition:
    any of them
}