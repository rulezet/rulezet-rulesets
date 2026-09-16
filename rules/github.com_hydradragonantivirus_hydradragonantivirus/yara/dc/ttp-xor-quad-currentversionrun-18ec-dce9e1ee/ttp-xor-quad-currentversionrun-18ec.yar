rule TTP_XOR_QUAD_CurrentVersionRun_18ec {
  strings:
    $key_18ec = { 4b 83 [2] 6f 8d [2] 44 a1 [2] 6a 83 [2] 7e 98 [2] 71 82 [2] 6f 9f [2] 6d 9e [2] 76 98 [2] 6a 9f [2] 76 b0 }

  condition:
    any of them
}