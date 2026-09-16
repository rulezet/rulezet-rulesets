rule TTP_XOR_MULT_DOSStub_33fb {
  strings:
    $key_33fb = { 67 93 [2] 13 8b [2] 54 89 [2] 13 98 [2] 5d 94 [2] 51 9e [2] 46 95 [2] 5d db [2] 60 }

  condition:
    any of them
}