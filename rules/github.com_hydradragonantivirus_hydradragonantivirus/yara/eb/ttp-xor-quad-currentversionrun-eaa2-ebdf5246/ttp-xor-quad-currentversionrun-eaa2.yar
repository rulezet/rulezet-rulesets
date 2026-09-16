rule TTP_XOR_QUAD_CurrentVersionRun_eaa2 {
  strings:
    $key_eaa2 = { b9 cd [2] 9d c3 [2] b6 ef [2] 98 cd [2] 8c d6 [2] 83 cc [2] 9d d1 [2] 9f d0 [2] 84 d6 [2] 98 d1 [2] 84 fe }

  condition:
    any of them
}