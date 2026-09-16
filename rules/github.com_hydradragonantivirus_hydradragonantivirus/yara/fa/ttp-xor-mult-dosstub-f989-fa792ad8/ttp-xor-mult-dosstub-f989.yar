rule TTP_XOR_MULT_DOSStub_f989 {
  strings:
    $key_f989 = { ad e1 [2] d9 f9 [2] 9e fb [2] d9 ea [2] 97 e6 [2] 9b ec [2] 8c e7 [2] 97 a9 [2] aa }

  condition:
    any of them
}