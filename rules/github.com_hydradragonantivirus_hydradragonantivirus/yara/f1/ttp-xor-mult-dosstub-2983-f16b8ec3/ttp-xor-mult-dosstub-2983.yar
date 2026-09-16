rule TTP_XOR_MULT_DOSStub_2983 {
  strings:
    $key_2983 = { 7d eb [2] 09 f3 [2] 4e f1 [2] 09 e0 [2] 47 ec [2] 4b e6 [2] 5c ed [2] 47 a3 [2] 7a }

  condition:
    any of them
}