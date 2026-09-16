rule TTP_XOR_MULT_DOSStub_eca3 {
  strings:
    $key_eca3 = { b8 cb [2] cc d3 [2] 8b d1 [2] cc c0 [2] 82 cc [2] 8e c6 [2] 99 cd [2] 82 83 [2] bf }

  condition:
    any of them
}