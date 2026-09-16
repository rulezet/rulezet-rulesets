rule TTP_XOR_QUAD_CurrentVersionRun_0ef8 {
  strings:
    $key_0ef8 = { 5d 97 [2] 79 99 [2] 52 b5 [2] 7c 97 [2] 68 8c [2] 67 96 [2] 79 8b [2] 7b 8a [2] 60 8c [2] 7c 8b [2] 60 a4 }

  condition:
    any of them
}