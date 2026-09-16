rule TTP_XOR_QUAD_CurrentVersionRun_dc8d {
  strings:
    $key_dc8d = { 8f e2 [2] ab ec [2] 80 c0 [2] ae e2 [2] ba f9 [2] b5 e3 [2] ab fe [2] a9 ff [2] b2 f9 [2] ae fe [2] b2 d1 }

  condition:
    any of them
}