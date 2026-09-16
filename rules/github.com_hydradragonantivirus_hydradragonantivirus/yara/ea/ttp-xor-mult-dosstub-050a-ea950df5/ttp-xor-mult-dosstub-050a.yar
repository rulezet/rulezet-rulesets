rule TTP_XOR_MULT_DOSStub_050a {
  strings:
    $key_050a = { 51 62 [2] 25 7a [2] 62 78 [2] 25 69 [2] 6b 65 [2] 67 6f [2] 70 64 [2] 6b 2a [2] 56 }

  condition:
    any of them
}