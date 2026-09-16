rule TTP_XOR_QUAD_CurrentVersionRun_55b1 {
  strings:
    $key_55b1 = { 06 de [2] 22 d0 [2] 09 fc [2] 27 de [2] 33 c5 [2] 3c df [2] 22 c2 [2] 20 c3 [2] 3b c5 [2] 27 c2 [2] 3b ed }

  condition:
    any of them
}