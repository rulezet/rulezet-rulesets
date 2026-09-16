rule TTP_XOR_MULT_DOSStub_def0 {
  strings:
    $key_def0 = { 8a 98 [2] fe 80 [2] b9 82 [2] fe 93 [2] b0 9f [2] bc 95 [2] ab 9e [2] b0 d0 [2] 8d }

  condition:
    any of them
}