rule TTP_XOR_MULT_DOSStub_6aa9 {
  strings:
    $key_6aa9 = { 3e c1 [2] 4a d9 [2] 0d db [2] 4a ca [2] 04 c6 [2] 08 cc [2] 1f c7 [2] 04 89 [2] 39 }

  condition:
    any of them
}