rule TTP_XOR_QUAD_CurrentVersionRun_3784 {
  strings:
    $key_3784 = { 64 eb [2] 40 e5 [2] 6b c9 [2] 45 eb [2] 51 f0 [2] 5e ea [2] 40 f7 [2] 42 f6 [2] 59 f0 [2] 45 f7 [2] 59 d8 }

  condition:
    any of them
}