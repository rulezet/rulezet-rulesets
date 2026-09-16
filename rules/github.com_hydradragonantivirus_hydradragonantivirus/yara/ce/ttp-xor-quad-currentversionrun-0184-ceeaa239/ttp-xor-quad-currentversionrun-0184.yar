rule TTP_XOR_QUAD_CurrentVersionRun_0184 {
  strings:
    $key_0184 = { 52 eb [2] 76 e5 [2] 5d c9 [2] 73 eb [2] 67 f0 [2] 68 ea [2] 76 f7 [2] 74 f6 [2] 6f f0 [2] 73 f7 [2] 6f d8 }

  condition:
    any of them
}