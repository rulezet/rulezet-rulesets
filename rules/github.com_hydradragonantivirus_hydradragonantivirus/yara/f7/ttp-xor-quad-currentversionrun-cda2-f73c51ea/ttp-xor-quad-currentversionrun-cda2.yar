rule TTP_XOR_QUAD_CurrentVersionRun_cda2 {
  strings:
    $key_cda2 = { 9e cd [2] ba c3 [2] 91 ef [2] bf cd [2] ab d6 [2] a4 cc [2] ba d1 [2] b8 d0 [2] a3 d6 [2] bf d1 [2] a3 fe }

  condition:
    any of them
}