rule TTP_XOR_QUAD_CurrentVersionRun_0ee0 {
  strings:
    $key_0ee0 = { 5d 8f [2] 79 81 [2] 52 ad [2] 7c 8f [2] 68 94 [2] 67 8e [2] 79 93 [2] 7b 92 [2] 60 94 [2] 7c 93 [2] 60 bc }

  condition:
    any of them
}