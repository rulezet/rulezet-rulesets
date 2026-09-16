rule TTP_XOR_MULT_DOSStub_cf84 {
  strings:
    $key_cf84 = { 9b ec [2] ef f4 [2] a8 f6 [2] ef e7 [2] a1 eb [2] ad e1 [2] ba ea [2] a1 a4 [2] 9c }

  condition:
    any of them
}