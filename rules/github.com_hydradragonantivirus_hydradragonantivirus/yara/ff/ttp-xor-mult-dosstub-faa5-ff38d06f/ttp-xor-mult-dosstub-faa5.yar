rule TTP_XOR_MULT_DOSStub_faa5 {
  strings:
    $key_faa5 = { ae cd [2] da d5 [2] 9d d7 [2] da c6 [2] 94 ca [2] 98 c0 [2] 8f cb [2] 94 85 [2] a9 }

  condition:
    any of them
}