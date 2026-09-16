rule TTP_XOR_QUAD_CurrentVersionRun_cca2 {
  strings:
    $key_cca2 = { 9f cd [2] bb c3 [2] 90 ef [2] be cd [2] aa d6 [2] a5 cc [2] bb d1 [2] b9 d0 [2] a2 d6 [2] be d1 [2] a2 fe }

  condition:
    any of them
}