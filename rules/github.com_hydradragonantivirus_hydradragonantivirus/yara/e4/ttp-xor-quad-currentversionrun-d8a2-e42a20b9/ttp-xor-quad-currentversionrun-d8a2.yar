rule TTP_XOR_QUAD_CurrentVersionRun_d8a2 {
  strings:
    $key_d8a2 = { 8b cd [2] af c3 [2] 84 ef [2] aa cd [2] be d6 [2] b1 cc [2] af d1 [2] ad d0 [2] b6 d6 [2] aa d1 [2] b6 fe }

  condition:
    any of them
}