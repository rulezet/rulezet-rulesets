rule TTP_XOR_QUAD_CurrentVersionRun_cba1 {
  strings:
    $key_cba1 = { 98 ce [2] bc c0 [2] 97 ec [2] b9 ce [2] ad d5 [2] a2 cf [2] bc d2 [2] be d3 [2] a5 d5 [2] b9 d2 [2] a5 fd }

  condition:
    any of them
}