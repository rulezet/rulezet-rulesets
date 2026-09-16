rule TTP_XOR_QUAD_CurrentVersionRun_c084 {
  strings:
    $key_c084 = { 93 eb [2] b7 e5 [2] 9c c9 [2] b2 eb [2] a6 f0 [2] a9 ea [2] b7 f7 [2] b5 f6 [2] ae f0 [2] b2 f7 [2] ae d8 }

  condition:
    any of them
}