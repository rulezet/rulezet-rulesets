rule TTP_XOR_QUAD_CurrentVersionRun_daac {
  strings:
    $key_daac = { 89 c3 [2] ad cd [2] 86 e1 [2] a8 c3 [2] bc d8 [2] b3 c2 [2] ad df [2] af de [2] b4 d8 [2] a8 df [2] b4 f0 }

  condition:
    any of them
}