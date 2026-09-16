rule TTP_XOR_QUAD_CurrentVersionRun_dfa2 {
  strings:
    $key_dfa2 = { 8c cd [2] a8 c3 [2] 83 ef [2] ad cd [2] b9 d6 [2] b6 cc [2] a8 d1 [2] aa d0 [2] b1 d6 [2] ad d1 [2] b1 fe }

  condition:
    any of them
}