rule TTP_XOR_QUAD_CurrentVersionRun_cde3 {
  strings:
    $key_cde3 = { 9e 8c [2] ba 82 [2] 91 ae [2] bf 8c [2] ab 97 [2] a4 8d [2] ba 90 [2] b8 91 [2] a3 97 [2] bf 90 [2] a3 bf }

  condition:
    any of them
}