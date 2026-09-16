rule TTP_XOR_QUAD_CurrentVersionRun_eb66 {
  strings:
    $key_eb66 = { b8 09 [2] 9c 07 [2] b7 2b [2] 99 09 [2] 8d 12 [2] 82 08 [2] 9c 15 [2] 9e 14 [2] 85 12 [2] 99 15 [2] 85 3a }

  condition:
    any of them
}