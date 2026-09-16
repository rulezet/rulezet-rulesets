rule TTP_XOR_MULT_DOSStub_dee5 {
  strings:
    $key_dee5 = { 8a 8d [2] fe 95 [2] b9 97 [2] fe 86 [2] b0 8a [2] bc 80 [2] ab 8b [2] b0 c5 [2] 8d }

  condition:
    any of them
}