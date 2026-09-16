rule TTP_XOR_MULT_DOSStub_ef88 {
  strings:
    $key_ef88 = { bb e0 [2] cf f8 [2] 88 fa [2] cf eb [2] 81 e7 [2] 8d ed [2] 9a e6 [2] 81 a8 [2] bc }

  condition:
    any of them
}