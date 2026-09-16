rule TTP_XOR_MULT_DOSStub_e9a9 {
  strings:
    $key_e9a9 = { bd c1 [2] c9 d9 [2] 8e db [2] c9 ca [2] 87 c6 [2] 8b cc [2] 9c c7 [2] 87 89 [2] ba }

  condition:
    any of them
}