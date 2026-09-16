rule TTP_XOR_QUAD_CurrentVersionRun_16b1 {
  strings:
    $key_16b1 = { 45 de [2] 61 d0 [2] 4a fc [2] 64 de [2] 70 c5 [2] 7f df [2] 61 c2 [2] 63 c3 [2] 78 c5 [2] 64 c2 [2] 78 ed }

  condition:
    any of them
}