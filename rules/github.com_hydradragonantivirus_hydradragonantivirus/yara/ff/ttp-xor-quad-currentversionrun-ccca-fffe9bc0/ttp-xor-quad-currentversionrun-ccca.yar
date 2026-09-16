rule TTP_XOR_QUAD_CurrentVersionRun_ccca {
  strings:
    $key_ccca = { 9f a5 [2] bb ab [2] 90 87 [2] be a5 [2] aa be [2] a5 a4 [2] bb b9 [2] b9 b8 [2] a2 be [2] be b9 [2] a2 96 }

  condition:
    any of them
}