rule TTP_XOR_QUAD_CurrentVersionRun_78ec {
  strings:
    $key_78ec = { 2b 83 [2] 0f 8d [2] 24 a1 [2] 0a 83 [2] 1e 98 [2] 11 82 [2] 0f 9f [2] 0d 9e [2] 16 98 [2] 0a 9f [2] 16 b0 }

  condition:
    any of them
}