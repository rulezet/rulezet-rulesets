rule TTP_XOR_QUAD_CurrentVersionRun_eb7d {
  strings:
    $key_eb7d = { b8 12 [2] 9c 1c [2] b7 30 [2] 99 12 [2] 8d 09 [2] 82 13 [2] 9c 0e [2] 9e 0f [2] 85 09 [2] 99 0e [2] 85 21 }

  condition:
    any of them
}