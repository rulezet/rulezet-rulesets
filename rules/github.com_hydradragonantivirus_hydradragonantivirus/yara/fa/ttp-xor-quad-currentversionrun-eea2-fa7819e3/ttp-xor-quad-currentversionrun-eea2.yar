rule TTP_XOR_QUAD_CurrentVersionRun_eea2 {
  strings:
    $key_eea2 = { bd cd [2] 99 c3 [2] b2 ef [2] 9c cd [2] 88 d6 [2] 87 cc [2] 99 d1 [2] 9b d0 [2] 80 d6 [2] 9c d1 [2] 80 fe }

  condition:
    any of them
}