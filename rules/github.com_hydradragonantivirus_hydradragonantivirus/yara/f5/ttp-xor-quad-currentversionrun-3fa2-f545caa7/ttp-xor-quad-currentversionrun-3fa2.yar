rule TTP_XOR_QUAD_CurrentVersionRun_3fa2 {
  strings:
    $key_3fa2 = { 6c cd [2] 48 c3 [2] 63 ef [2] 4d cd [2] 59 d6 [2] 56 cc [2] 48 d1 [2] 4a d0 [2] 51 d6 [2] 4d d1 [2] 51 fe }

  condition:
    any of them
}