rule TTP_XOR_MULT_DOSStub_ee83 {
  strings:
    $key_ee83 = { ba eb [2] ce f3 [2] 89 f1 [2] ce e0 [2] 80 ec [2] 8c e6 [2] 9b ed [2] 80 a3 [2] bd }

  condition:
    any of them
}