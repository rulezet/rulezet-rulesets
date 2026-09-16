rule TTP_XOR_QUAD_CurrentVersionRun_cdd0 {
  strings:
    $key_cdd0 = { 9e bf [2] ba b1 [2] 91 9d [2] bf bf [2] ab a4 [2] a4 be [2] ba a3 [2] b8 a2 [2] a3 a4 [2] bf a3 [2] a3 8c }

  condition:
    any of them
}