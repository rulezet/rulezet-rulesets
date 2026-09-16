rule TTP_XOR_QUAD_CurrentVersionRun_db9f {
  strings:
    $key_db9f = { 88 f0 [2] ac fe [2] 87 d2 [2] a9 f0 [2] bd eb [2] b2 f1 [2] ac ec [2] ae ed [2] b5 eb [2] a9 ec [2] b5 c3 }

  condition:
    any of them
}