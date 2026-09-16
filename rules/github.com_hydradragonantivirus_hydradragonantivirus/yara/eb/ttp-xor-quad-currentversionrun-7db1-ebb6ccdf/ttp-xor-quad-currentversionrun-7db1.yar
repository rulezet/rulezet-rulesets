rule TTP_XOR_QUAD_CurrentVersionRun_7db1 {
  strings:
    $key_7db1 = { 2e de [2] 0a d0 [2] 21 fc [2] 0f de [2] 1b c5 [2] 14 df [2] 0a c2 [2] 08 c3 [2] 13 c5 [2] 0f c2 [2] 13 ed }

  condition:
    any of them
}