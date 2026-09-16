rule TTP_XOR_MULT_DOSStub_faa9 {
  strings:
    $key_faa9 = { ae c1 [2] da d9 [2] 9d db [2] da ca [2] 94 c6 [2] 98 cc [2] 8f c7 [2] 94 89 [2] a9 }

  condition:
    any of them
}