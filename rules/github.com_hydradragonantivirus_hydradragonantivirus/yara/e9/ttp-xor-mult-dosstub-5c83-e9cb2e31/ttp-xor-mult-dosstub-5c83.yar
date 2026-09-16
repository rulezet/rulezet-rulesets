rule TTP_XOR_MULT_DOSStub_5c83 {
  strings:
    $key_5c83 = { 08 eb [2] 7c f3 [2] 3b f1 [2] 7c e0 [2] 32 ec [2] 3e e6 [2] 29 ed [2] 32 a3 [2] 0f }

  condition:
    any of them
}