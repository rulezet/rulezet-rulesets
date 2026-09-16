rule TTP_XOR_QUAD_CurrentVersionRun_c4ec {
  strings:
    $key_c4ec = { 97 83 [2] b3 8d [2] 98 a1 [2] b6 83 [2] a2 98 [2] ad 82 [2] b3 9f [2] b1 9e [2] aa 98 [2] b6 9f [2] aa b0 }

  condition:
    any of them
}