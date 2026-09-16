rule TTP_XOR_MULT_DOSStub_dee1 {
  strings:
    $key_dee1 = { 8a 89 [2] fe 91 [2] b9 93 [2] fe 82 [2] b0 8e [2] bc 84 [2] ab 8f [2] b0 c1 [2] 8d }

  condition:
    any of them
}