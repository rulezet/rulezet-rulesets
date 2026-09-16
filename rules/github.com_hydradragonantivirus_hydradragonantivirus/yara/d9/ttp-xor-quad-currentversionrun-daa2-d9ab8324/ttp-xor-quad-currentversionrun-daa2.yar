rule TTP_XOR_QUAD_CurrentVersionRun_daa2 {
  strings:
    $key_daa2 = { 89 cd [2] ad c3 [2] 86 ef [2] a8 cd [2] bc d6 [2] b3 cc [2] ad d1 [2] af d0 [2] b4 d6 [2] a8 d1 [2] b4 fe }

  condition:
    any of them
}