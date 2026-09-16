rule TTP_XOR_MULT_DOSStub_ef8a {
  strings:
    $key_ef8a = { bb e2 [2] cf fa [2] 88 f8 [2] cf e9 [2] 81 e5 [2] 8d ef [2] 9a e4 [2] 81 aa [2] bc }

  condition:
    any of them
}