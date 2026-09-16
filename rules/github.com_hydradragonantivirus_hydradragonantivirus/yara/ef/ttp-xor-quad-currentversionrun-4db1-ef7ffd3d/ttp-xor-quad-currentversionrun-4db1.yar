rule TTP_XOR_QUAD_CurrentVersionRun_4db1 {
  strings:
    $key_4db1 = { 1e de [2] 3a d0 [2] 11 fc [2] 3f de [2] 2b c5 [2] 24 df [2] 3a c2 [2] 38 c3 [2] 23 c5 [2] 3f c2 [2] 23 ed }

  condition:
    any of them
}