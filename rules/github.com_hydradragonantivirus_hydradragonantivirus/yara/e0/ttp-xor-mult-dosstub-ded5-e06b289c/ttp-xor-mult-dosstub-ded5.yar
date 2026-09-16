rule TTP_XOR_MULT_DOSStub_ded5 {
  strings:
    $key_ded5 = { 8a bd [2] fe a5 [2] b9 a7 [2] fe b6 [2] b0 ba [2] bc b0 [2] ab bb [2] b0 f5 [2] 8d }

  condition:
    any of them
}