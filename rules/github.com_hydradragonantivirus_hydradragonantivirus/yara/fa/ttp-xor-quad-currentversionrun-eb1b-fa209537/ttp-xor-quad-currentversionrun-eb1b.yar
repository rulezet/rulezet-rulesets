rule TTP_XOR_QUAD_CurrentVersionRun_eb1b {
  strings:
    $key_eb1b = { b8 74 [2] 9c 7a [2] b7 56 [2] 99 74 [2] 8d 6f [2] 82 75 [2] 9c 68 [2] 9e 69 [2] 85 6f [2] 99 68 [2] 85 47 }

  condition:
    any of them
}