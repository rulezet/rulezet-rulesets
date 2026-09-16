rule TTP_XOR_QUAD_CurrentVersionRun_eb13 {
  strings:
    $key_eb13 = { b8 7c [2] 9c 72 [2] b7 5e [2] 99 7c [2] 8d 67 [2] 82 7d [2] 9c 60 [2] 9e 61 [2] 85 67 [2] 99 60 [2] 85 4f }

  condition:
    any of them
}