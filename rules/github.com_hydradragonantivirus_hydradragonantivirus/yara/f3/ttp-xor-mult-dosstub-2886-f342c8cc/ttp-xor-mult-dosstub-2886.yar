rule TTP_XOR_MULT_DOSStub_2886 {
  strings:
    $key_2886 = { 7c ee [2] 08 f6 [2] 4f f4 [2] 08 e5 [2] 46 e9 [2] 4a e3 [2] 5d e8 [2] 46 a6 [2] 7b }

  condition:
    any of them
}