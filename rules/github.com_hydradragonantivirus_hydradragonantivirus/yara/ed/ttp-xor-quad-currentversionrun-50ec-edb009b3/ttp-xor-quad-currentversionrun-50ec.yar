rule TTP_XOR_QUAD_CurrentVersionRun_50ec {
  strings:
    $key_50ec = { 03 83 [2] 27 8d [2] 0c a1 [2] 22 83 [2] 36 98 [2] 39 82 [2] 27 9f [2] 25 9e [2] 3e 98 [2] 22 9f [2] 3e b0 }

  condition:
    any of them
}