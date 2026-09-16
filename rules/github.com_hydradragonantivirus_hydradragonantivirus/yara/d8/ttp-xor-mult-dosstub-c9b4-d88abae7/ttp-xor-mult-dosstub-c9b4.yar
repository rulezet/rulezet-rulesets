rule TTP_XOR_MULT_DOSStub_c9b4 {
  strings:
    $key_c9b4 = { 9d dc [2] e9 c4 [2] ae c6 [2] e9 d7 [2] a7 db [2] ab d1 [2] bc da [2] a7 94 [2] 9a }

  condition:
    any of them
}