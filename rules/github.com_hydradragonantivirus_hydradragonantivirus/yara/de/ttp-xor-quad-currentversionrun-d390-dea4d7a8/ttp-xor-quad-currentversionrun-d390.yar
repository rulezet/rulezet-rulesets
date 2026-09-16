rule TTP_XOR_QUAD_CurrentVersionRun_d390 {
  strings:
    $key_d390 = { 80 ff [2] a4 f1 [2] 8f dd [2] a1 ff [2] b5 e4 [2] ba fe [2] a4 e3 [2] a6 e2 [2] bd e4 [2] a1 e3 [2] bd cc }

  condition:
    any of them
}