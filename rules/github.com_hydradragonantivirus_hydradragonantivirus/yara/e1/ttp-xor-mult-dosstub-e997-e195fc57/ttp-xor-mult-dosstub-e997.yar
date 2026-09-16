rule TTP_XOR_MULT_DOSStub_e997 {
  strings:
    $key_e997 = { bd ff [2] c9 e7 [2] 8e e5 [2] c9 f4 [2] 87 f8 [2] 8b f2 [2] 9c f9 [2] 87 b7 [2] ba }

  condition:
    any of them
}