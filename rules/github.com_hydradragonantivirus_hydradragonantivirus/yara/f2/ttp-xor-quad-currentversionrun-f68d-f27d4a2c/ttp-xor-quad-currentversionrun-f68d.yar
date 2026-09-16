rule TTP_XOR_QUAD_CurrentVersionRun_f68d {
  strings:
    $key_f68d = { a5 e2 [2] 81 ec [2] aa c0 [2] 84 e2 [2] 90 f9 [2] 9f e3 [2] 81 fe [2] 83 ff [2] 98 f9 [2] 84 fe [2] 98 d1 }

  condition:
    any of them
}