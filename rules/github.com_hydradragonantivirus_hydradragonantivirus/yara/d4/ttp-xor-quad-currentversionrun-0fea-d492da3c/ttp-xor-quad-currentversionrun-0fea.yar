rule TTP_XOR_QUAD_CurrentVersionRun_0fea {
  strings:
    $key_0fea = { 5c 85 [2] 78 8b [2] 53 a7 [2] 7d 85 [2] 69 9e [2] 66 84 [2] 78 99 [2] 7a 98 [2] 61 9e [2] 7d 99 [2] 61 b6 }

  condition:
    any of them
}