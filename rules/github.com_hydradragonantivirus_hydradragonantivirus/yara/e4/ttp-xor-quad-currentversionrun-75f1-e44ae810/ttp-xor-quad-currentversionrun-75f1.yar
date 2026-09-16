rule TTP_XOR_QUAD_CurrentVersionRun_75f1 {
  strings:
    $key_75f1 = { 26 9e [2] 02 90 [2] 29 bc [2] 07 9e [2] 13 85 [2] 1c 9f [2] 02 82 [2] 00 83 [2] 1b 85 [2] 07 82 [2] 1b ad }

  condition:
    any of them
}