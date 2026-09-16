rule TTP_XOR_MULT_DOSStub_dee0 {
  strings:
    $key_dee0 = { 8a 88 [2] fe 90 [2] b9 92 [2] fe 83 [2] b0 8f [2] bc 85 [2] ab 8e [2] b0 c0 [2] 8d }

  condition:
    any of them
}