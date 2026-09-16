rule TTP_XOR_QUAD_CurrentVersionRun_c093 {
  strings:
    $key_c093 = { 93 fc [2] b7 f2 [2] 9c de [2] b2 fc [2] a6 e7 [2] a9 fd [2] b7 e0 [2] b5 e1 [2] ae e7 [2] b2 e0 [2] ae cf }

  condition:
    any of them
}