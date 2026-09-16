rule TTP_XOR_QUAD_CurrentVersionRun_0aa2 {
  strings:
    $key_0aa2 = { 59 cd [2] 7d c3 [2] 56 ef [2] 78 cd [2] 6c d6 [2] 63 cc [2] 7d d1 [2] 7f d0 [2] 64 d6 [2] 78 d1 [2] 64 fe }

  condition:
    any of them
}