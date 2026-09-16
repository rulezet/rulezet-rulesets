rule TTP_XOR_MULT_DOSStub_caa9 {
  strings:
    $key_caa9 = { 9e c1 [2] ea d9 [2] ad db [2] ea ca [2] a4 c6 [2] a8 cc [2] bf c7 [2] a4 89 [2] 99 }

  condition:
    any of them
}