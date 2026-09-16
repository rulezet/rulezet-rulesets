rule TTP_XOR_MULT_DOSStub_efd3 {
  strings:
    $key_efd3 = { bb bb [2] cf a3 [2] 88 a1 [2] cf b0 [2] 81 bc [2] 8d b6 [2] 9a bd [2] 81 f3 [2] bc }

  condition:
    any of them
}