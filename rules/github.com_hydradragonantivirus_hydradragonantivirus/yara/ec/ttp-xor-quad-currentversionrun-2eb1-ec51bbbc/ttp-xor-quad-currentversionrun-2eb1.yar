rule TTP_XOR_QUAD_CurrentVersionRun_2eb1 {
  strings:
    $key_2eb1 = { 7d de [2] 59 d0 [2] 72 fc [2] 5c de [2] 48 c5 [2] 47 df [2] 59 c2 [2] 5b c3 [2] 40 c5 [2] 5c c2 [2] 40 ed }

  condition:
    any of them
}