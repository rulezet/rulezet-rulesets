rule TTP_XOR_MULT_DOSStub_def5 {
  strings:
    $key_def5 = { 8a 9d [2] fe 85 [2] b9 87 [2] fe 96 [2] b0 9a [2] bc 90 [2] ab 9b [2] b0 d5 [2] 8d }

  condition:
    any of them
}