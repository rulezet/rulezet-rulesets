rule TTP_XOR_QUAD_CurrentVersionRun_1cb1 {
  strings:
    $key_1cb1 = { 4f de [2] 6b d0 [2] 40 fc [2] 6e de [2] 7a c5 [2] 75 df [2] 6b c2 [2] 69 c3 [2] 72 c5 [2] 6e c2 [2] 72 ed }

  condition:
    any of them
}