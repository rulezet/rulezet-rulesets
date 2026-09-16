rule TTP_XOR_MULT_DOSStub_cf83 {
  strings:
    $key_cf83 = { 9b eb [2] ef f3 [2] a8 f1 [2] ef e0 [2] a1 ec [2] ad e6 [2] ba ed [2] a1 a3 [2] 9c }

  condition:
    any of them
}