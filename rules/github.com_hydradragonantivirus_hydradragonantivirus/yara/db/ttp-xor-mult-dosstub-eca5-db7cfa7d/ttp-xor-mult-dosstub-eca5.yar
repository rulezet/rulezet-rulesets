rule TTP_XOR_MULT_DOSStub_eca5 {
  strings:
    $key_eca5 = { b8 cd [2] cc d5 [2] 8b d7 [2] cc c6 [2] 82 ca [2] 8e c0 [2] 99 cb [2] 82 85 [2] bf }

  condition:
    any of them
}