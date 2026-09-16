rule TTP_XOR_QUAD_CurrentVersionRun_eb7f {
  strings:
    $key_eb7f = { b8 10 [2] 9c 1e [2] b7 32 [2] 99 10 [2] 8d 0b [2] 82 11 [2] 9c 0c [2] 9e 0d [2] 85 0b [2] 99 0c [2] 85 23 }

  condition:
    any of them
}