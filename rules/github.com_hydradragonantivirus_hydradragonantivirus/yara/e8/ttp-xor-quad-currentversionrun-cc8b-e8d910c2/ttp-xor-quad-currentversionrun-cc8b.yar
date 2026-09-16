rule TTP_XOR_QUAD_CurrentVersionRun_cc8b {
  strings:
    $key_cc8b = { 9f e4 [2] bb ea [2] 90 c6 [2] be e4 [2] aa ff [2] a5 e5 [2] bb f8 [2] b9 f9 [2] a2 ff [2] be f8 [2] a2 d7 }

  condition:
    any of them
}