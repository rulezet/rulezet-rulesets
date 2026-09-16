rule TTP_XOR_QUAD_CurrentVersionRun_2cb1 {
  strings:
    $key_2cb1 = { 7f de [2] 5b d0 [2] 70 fc [2] 5e de [2] 4a c5 [2] 45 df [2] 5b c2 [2] 59 c3 [2] 42 c5 [2] 5e c2 [2] 42 ed }

  condition:
    any of them
}