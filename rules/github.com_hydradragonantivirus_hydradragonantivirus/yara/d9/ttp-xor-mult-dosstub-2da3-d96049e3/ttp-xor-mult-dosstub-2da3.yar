rule TTP_XOR_MULT_DOSStub_2da3 {
  strings:
    $key_2da3 = { 79 cb [2] 0d d3 [2] 4a d1 [2] 0d c0 [2] 43 cc [2] 4f c6 [2] 58 cd [2] 43 83 [2] 7e }

  condition:
    any of them
}