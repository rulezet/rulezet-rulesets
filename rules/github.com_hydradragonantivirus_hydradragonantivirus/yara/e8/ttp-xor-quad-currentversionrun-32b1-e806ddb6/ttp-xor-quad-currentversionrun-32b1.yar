rule TTP_XOR_QUAD_CurrentVersionRun_32b1 {
  strings:
    $key_32b1 = { 61 de [2] 45 d0 [2] 6e fc [2] 40 de [2] 54 c5 [2] 5b df [2] 45 c2 [2] 47 c3 [2] 5c c5 [2] 40 c2 [2] 5c ed }

  condition:
    any of them
}