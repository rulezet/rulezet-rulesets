rule TTP_XOR_QUAD_CurrentVersionRun_1aa2 {
  strings:
    $key_1aa2 = { 49 cd [2] 6d c3 [2] 46 ef [2] 68 cd [2] 7c d6 [2] 73 cc [2] 6d d1 [2] 6f d0 [2] 74 d6 [2] 68 d1 [2] 74 fe }

  condition:
    any of them
}