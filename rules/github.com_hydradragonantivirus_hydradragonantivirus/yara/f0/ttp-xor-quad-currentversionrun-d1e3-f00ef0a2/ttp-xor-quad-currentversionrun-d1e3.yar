rule TTP_XOR_QUAD_CurrentVersionRun_d1e3 {
  strings:
    $key_d1e3 = { 82 8c [2] a6 82 [2] 8d ae [2] a3 8c [2] b7 97 [2] b8 8d [2] a6 90 [2] a4 91 [2] bf 97 [2] a3 90 [2] bf bf }

  condition:
    any of them
}