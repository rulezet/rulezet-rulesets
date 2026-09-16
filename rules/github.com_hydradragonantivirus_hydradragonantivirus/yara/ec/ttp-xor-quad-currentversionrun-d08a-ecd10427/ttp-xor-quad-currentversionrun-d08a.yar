rule TTP_XOR_QUAD_CurrentVersionRun_d08a {
  strings:
    $key_d08a = { 83 e5 [2] a7 eb [2] 8c c7 [2] a2 e5 [2] b6 fe [2] b9 e4 [2] a7 f9 [2] a5 f8 [2] be fe [2] a2 f9 [2] be d6 }

  condition:
    any of them
}