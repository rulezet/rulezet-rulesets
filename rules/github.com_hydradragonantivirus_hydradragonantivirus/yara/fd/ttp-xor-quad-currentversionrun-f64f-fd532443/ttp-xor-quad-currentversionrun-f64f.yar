rule TTP_XOR_QUAD_CurrentVersionRun_f64f {
  strings:
    $key_f64f = { a5 20 [2] 81 2e [2] aa 02 [2] 84 20 [2] 90 3b [2] 9f 21 [2] 81 3c [2] 83 3d [2] 98 3b [2] 84 3c [2] 98 13 }

  condition:
    any of them
}