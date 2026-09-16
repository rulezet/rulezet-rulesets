rule TTP_XOR_MULT_DOSStub_0237 {
  strings:
    $key_0237 = { 56 5f [2] 22 47 [2] 65 45 [2] 22 54 [2] 6c 58 [2] 60 52 [2] 77 59 [2] 6c 17 [2] 51 }

  condition:
    any of them
}