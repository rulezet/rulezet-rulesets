rule TTP_XOR_QUAD_CurrentVersionRun_db8d {
  strings:
    $key_db8d = { 88 e2 [2] ac ec [2] 87 c0 [2] a9 e2 [2] bd f9 [2] b2 e3 [2] ac fe [2] ae ff [2] b5 f9 [2] a9 fe [2] b5 d1 }

  condition:
    any of them
}