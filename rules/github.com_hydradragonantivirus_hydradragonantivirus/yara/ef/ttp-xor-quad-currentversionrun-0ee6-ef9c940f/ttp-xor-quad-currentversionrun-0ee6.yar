rule TTP_XOR_QUAD_CurrentVersionRun_0ee6 {
  strings:
    $key_0ee6 = { 5d 89 [2] 79 87 [2] 52 ab [2] 7c 89 [2] 68 92 [2] 67 88 [2] 79 95 [2] 7b 94 [2] 60 92 [2] 7c 95 [2] 60 ba }

  condition:
    any of them
}