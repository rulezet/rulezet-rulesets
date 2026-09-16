rule TTP_XOR_QUAD_CurrentVersionRun_d084 {
  strings:
    $key_d084 = { 83 eb [2] a7 e5 [2] 8c c9 [2] a2 eb [2] b6 f0 [2] b9 ea [2] a7 f7 [2] a5 f6 [2] be f0 [2] a2 f7 [2] be d8 }

  condition:
    any of them
}