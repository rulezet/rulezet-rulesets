rule TTP_XOR_QUAD_CurrentVersionRun_daad {
  strings:
    $key_daad = { 89 c2 [2] ad cc [2] 86 e0 [2] a8 c2 [2] bc d9 [2] b3 c3 [2] ad de [2] af df [2] b4 d9 [2] a8 de [2] b4 f1 }

  condition:
    any of them
}