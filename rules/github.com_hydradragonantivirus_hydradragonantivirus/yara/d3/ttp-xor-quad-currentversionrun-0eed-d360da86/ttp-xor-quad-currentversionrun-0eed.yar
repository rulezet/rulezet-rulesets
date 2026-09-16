rule TTP_XOR_QUAD_CurrentVersionRun_0eed {
  strings:
    $key_0eed = { 5d 82 [2] 79 8c [2] 52 a0 [2] 7c 82 [2] 68 99 [2] 67 83 [2] 79 9e [2] 7b 9f [2] 60 99 [2] 7c 9e [2] 60 b1 }

  condition:
    any of them
}