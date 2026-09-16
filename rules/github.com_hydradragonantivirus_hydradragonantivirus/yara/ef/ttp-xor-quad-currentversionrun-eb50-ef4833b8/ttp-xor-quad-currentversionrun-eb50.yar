rule TTP_XOR_QUAD_CurrentVersionRun_eb50 {
  strings:
    $key_eb50 = { b8 3f [2] 9c 31 [2] b7 1d [2] 99 3f [2] 8d 24 [2] 82 3e [2] 9c 23 [2] 9e 22 [2] 85 24 [2] 99 23 [2] 85 0c }

  condition:
    any of them
}