rule TTP_XOR_MULT_DOSStub_c986 {
  strings:
    $key_c986 = { 9d ee [2] e9 f6 [2] ae f4 [2] e9 e5 [2] a7 e9 [2] ab e3 [2] bc e8 [2] a7 a6 [2] 9a }

  condition:
    any of them
}