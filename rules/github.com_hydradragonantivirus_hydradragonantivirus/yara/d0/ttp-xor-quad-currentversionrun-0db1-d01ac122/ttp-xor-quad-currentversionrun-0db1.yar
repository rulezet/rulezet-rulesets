rule TTP_XOR_QUAD_CurrentVersionRun_0db1 {
  strings:
    $key_0db1 = { 5e de [2] 7a d0 [2] 51 fc [2] 7f de [2] 6b c5 [2] 64 df [2] 7a c2 [2] 78 c3 [2] 63 c5 [2] 7f c2 [2] 63 ed }

  condition:
    any of them
}