rule TTP_XOR_QUAD_CurrentVersionRun_75b1 {
  strings:
    $key_75b1 = { 26 de [2] 02 d0 [2] 29 fc [2] 07 de [2] 13 c5 [2] 1c df [2] 02 c2 [2] 00 c3 [2] 1b c5 [2] 07 c2 [2] 1b ed }

  condition:
    any of them
}