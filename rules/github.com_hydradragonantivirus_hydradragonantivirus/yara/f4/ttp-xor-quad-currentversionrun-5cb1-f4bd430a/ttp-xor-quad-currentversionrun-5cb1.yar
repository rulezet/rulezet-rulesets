rule TTP_XOR_QUAD_CurrentVersionRun_5cb1 {
  strings:
    $key_5cb1 = { 0f de [2] 2b d0 [2] 00 fc [2] 2e de [2] 3a c5 [2] 35 df [2] 2b c2 [2] 29 c3 [2] 32 c5 [2] 2e c2 [2] 32 ed }

  condition:
    any of them
}