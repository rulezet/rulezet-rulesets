rule TTP_XOR_MULT_DOSStub_43f3 {
  strings:
    $key_43f3 = { 17 9b [2] 63 83 [2] 24 81 [2] 63 90 [2] 2d 9c [2] 21 96 [2] 36 9d [2] 2d d3 [2] 10 }

  condition:
    any of them
}