rule TTP_XOR_QUAD_CurrentVersionRun_0699 {
  strings:
    $key_0699 = { 55 f6 [2] 71 f8 [2] 5a d4 [2] 74 f6 [2] 60 ed [2] 6f f7 [2] 71 ea [2] 73 eb [2] 68 ed [2] 74 ea [2] 68 c5 }

  condition:
    any of them
}