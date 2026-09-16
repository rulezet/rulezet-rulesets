rule TTP_XOR_QUAD_CurrentVersionRun_2484 {
  strings:
    $key_2484 = { 77 eb [2] 53 e5 [2] 78 c9 [2] 56 eb [2] 42 f0 [2] 4d ea [2] 53 f7 [2] 51 f6 [2] 4a f0 [2] 56 f7 [2] 4a d8 }

  condition:
    any of them
}