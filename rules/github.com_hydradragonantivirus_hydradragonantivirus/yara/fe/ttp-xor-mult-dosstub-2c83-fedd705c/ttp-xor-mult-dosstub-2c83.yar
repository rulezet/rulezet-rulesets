rule TTP_XOR_MULT_DOSStub_2c83 {
  strings:
    $key_2c83 = { 78 eb [2] 0c f3 [2] 4b f1 [2] 0c e0 [2] 42 ec [2] 4e e6 [2] 59 ed [2] 42 a3 [2] 7f }

  condition:
    any of them
}