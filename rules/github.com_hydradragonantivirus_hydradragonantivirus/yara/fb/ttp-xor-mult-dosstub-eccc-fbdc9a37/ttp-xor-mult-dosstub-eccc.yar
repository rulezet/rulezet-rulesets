rule TTP_XOR_MULT_DOSStub_eccc {
  strings:
    $key_eccc = { b8 a4 [2] cc bc [2] 8b be [2] cc af [2] 82 a3 [2] 8e a9 [2] 99 a2 [2] 82 ec [2] bf }

  condition:
    any of them
}