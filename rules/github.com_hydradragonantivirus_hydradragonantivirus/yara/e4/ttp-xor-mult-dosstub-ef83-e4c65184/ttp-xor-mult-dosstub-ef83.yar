rule TTP_XOR_MULT_DOSStub_ef83 {
  strings:
    $key_ef83 = { bb eb [2] cf f3 [2] 88 f1 [2] cf e0 [2] 81 ec [2] 8d e6 [2] 9a ed [2] 81 a3 [2] bc }

  condition:
    any of them
}