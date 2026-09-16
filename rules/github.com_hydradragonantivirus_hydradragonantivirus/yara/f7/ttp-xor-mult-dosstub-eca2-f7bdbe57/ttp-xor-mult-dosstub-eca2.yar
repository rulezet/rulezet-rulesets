rule TTP_XOR_MULT_DOSStub_eca2 {
  strings:
    $key_eca2 = { b8 ca [2] cc d2 [2] 8b d0 [2] cc c1 [2] 82 cd [2] 8e c7 [2] 99 cc [2] 82 82 [2] bf }

  condition:
    any of them
}