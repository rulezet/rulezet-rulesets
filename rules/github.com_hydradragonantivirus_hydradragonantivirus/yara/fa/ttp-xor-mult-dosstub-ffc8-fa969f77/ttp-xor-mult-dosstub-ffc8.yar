rule TTP_XOR_MULT_DOSStub_ffc8 {
  strings:
    $key_ffc8 = { ab a0 [2] df b8 [2] 98 ba [2] df ab [2] 91 a7 [2] 9d ad [2] 8a a6 [2] 91 e8 [2] ac }

  condition:
    any of them
}