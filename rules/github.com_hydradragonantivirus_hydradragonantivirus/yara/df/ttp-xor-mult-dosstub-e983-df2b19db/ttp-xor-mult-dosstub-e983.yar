rule TTP_XOR_MULT_DOSStub_e983 {
  strings:
    $key_e983 = { bd eb [2] c9 f3 [2] 8e f1 [2] c9 e0 [2] 87 ec [2] 8b e6 [2] 9c ed [2] 87 a3 [2] ba }

  condition:
    any of them
}