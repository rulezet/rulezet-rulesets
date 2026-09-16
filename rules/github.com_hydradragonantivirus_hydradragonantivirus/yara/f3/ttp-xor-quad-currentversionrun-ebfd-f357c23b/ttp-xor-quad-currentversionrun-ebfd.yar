rule TTP_XOR_QUAD_CurrentVersionRun_ebfd {
  strings:
    $key_ebfd = { b8 92 [2] 9c 9c [2] b7 b0 [2] 99 92 [2] 8d 89 [2] 82 93 [2] 9c 8e [2] 9e 8f [2] 85 89 [2] 99 8e [2] 85 a1 }

  condition:
    any of them
}