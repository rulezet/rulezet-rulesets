rule TTP_XOR_MULT_DOSStub_ded7 {
  strings:
    $key_ded7 = { 8a bf [2] fe a7 [2] b9 a5 [2] fe b4 [2] b0 b8 [2] bc b2 [2] ab b9 [2] b0 f7 [2] 8d }

  condition:
    any of them
}