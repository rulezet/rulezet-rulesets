rule TTP_XOR_QUAD_CurrentVersionRun_3291 {
  strings:
    $key_3291 = { 61 fe [2] 45 f0 [2] 6e dc [2] 40 fe [2] 54 e5 [2] 5b ff [2] 45 e2 [2] 47 e3 [2] 5c e5 [2] 40 e2 [2] 5c cd }

  condition:
    any of them
}