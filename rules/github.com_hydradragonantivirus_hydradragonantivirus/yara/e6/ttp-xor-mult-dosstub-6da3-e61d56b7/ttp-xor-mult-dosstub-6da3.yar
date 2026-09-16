rule TTP_XOR_MULT_DOSStub_6da3 {
  strings:
    $key_6da3 = { 39 cb [2] 4d d3 [2] 0a d1 [2] 4d c0 [2] 03 cc [2] 0f c6 [2] 18 cd [2] 03 83 [2] 3e }

  condition:
    any of them
}