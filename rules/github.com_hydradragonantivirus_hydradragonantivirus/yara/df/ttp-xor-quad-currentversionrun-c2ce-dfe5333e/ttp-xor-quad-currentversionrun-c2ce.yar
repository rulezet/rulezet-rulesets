rule TTP_XOR_QUAD_CurrentVersionRun_c2ce {
  strings:
    $key_c2ce = { 91 a1 [2] b5 af [2] 9e 83 [2] b0 a1 [2] a4 ba [2] ab a0 [2] b5 bd [2] b7 bc [2] ac ba [2] b0 bd [2] ac 92 }

  condition:
    any of them
}