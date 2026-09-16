rule TTP_XOR_QUAD_CurrentVersionRun_65b1 {
  strings:
    $key_65b1 = { 36 de [2] 12 d0 [2] 39 fc [2] 17 de [2] 03 c5 [2] 0c df [2] 12 c2 [2] 10 c3 [2] 0b c5 [2] 17 c2 [2] 0b ed }

  condition:
    any of them
}