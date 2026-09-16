rule TTP_XOR_MULT_DOSStub_19a9 {
  strings:
    $key_19a9 = { 4d c1 [2] 39 d9 [2] 7e db [2] 39 ca [2] 77 c6 [2] 7b cc [2] 6c c7 [2] 77 89 [2] 4a }

  condition:
    any of them
}