rule TTP_XOR_QUAD_CurrentVersionRun_eb20 {
  strings:
    $key_eb20 = { b8 4f [2] 9c 41 [2] b7 6d [2] 99 4f [2] 8d 54 [2] 82 4e [2] 9c 53 [2] 9e 52 [2] 85 54 [2] 99 53 [2] 85 7c }

  condition:
    any of them
}