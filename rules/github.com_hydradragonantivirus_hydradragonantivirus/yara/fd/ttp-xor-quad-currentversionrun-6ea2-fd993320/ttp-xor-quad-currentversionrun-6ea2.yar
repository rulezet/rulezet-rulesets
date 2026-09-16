rule TTP_XOR_QUAD_CurrentVersionRun_6ea2 {
  strings:
    $key_6ea2 = { 3d cd [2] 19 c3 [2] 32 ef [2] 1c cd [2] 08 d6 [2] 07 cc [2] 19 d1 [2] 1b d0 [2] 00 d6 [2] 1c d1 [2] 00 fe }

  condition:
    any of them
}