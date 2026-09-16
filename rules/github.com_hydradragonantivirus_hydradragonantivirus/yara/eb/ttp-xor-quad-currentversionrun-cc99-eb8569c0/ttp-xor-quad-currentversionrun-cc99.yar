rule TTP_XOR_QUAD_CurrentVersionRun_cc99 {
  strings:
    $key_cc99 = { 9f f6 [2] bb f8 [2] 90 d4 [2] be f6 [2] aa ed [2] a5 f7 [2] bb ea [2] b9 eb [2] a2 ed [2] be ea [2] a2 c5 }

  condition:
    any of them
}