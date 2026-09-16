rule TTP_XOR_MULT_DOSStub_0da3 {
  strings:
    $key_0da3 = { 59 cb [2] 2d d3 [2] 6a d1 [2] 2d c0 [2] 63 cc [2] 6f c6 [2] 78 cd [2] 63 83 [2] 5e }

  condition:
    any of them
}