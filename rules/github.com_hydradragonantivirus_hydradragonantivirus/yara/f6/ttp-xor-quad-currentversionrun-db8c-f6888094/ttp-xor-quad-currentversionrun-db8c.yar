rule TTP_XOR_QUAD_CurrentVersionRun_db8c {
  strings:
    $key_db8c = { 88 e3 [2] ac ed [2] 87 c1 [2] a9 e3 [2] bd f8 [2] b2 e2 [2] ac ff [2] ae fe [2] b5 f8 [2] a9 ff [2] b5 d0 }

  condition:
    any of them
}