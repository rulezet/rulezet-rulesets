rule TTP_XOR_QUAD_CurrentVersionRun_0eea {
  strings:
    $key_0eea = { 5d 85 [2] 79 8b [2] 52 a7 [2] 7c 85 [2] 68 9e [2] 67 84 [2] 79 99 [2] 7b 98 [2] 60 9e [2] 7c 99 [2] 60 b6 }

  condition:
    any of them
}