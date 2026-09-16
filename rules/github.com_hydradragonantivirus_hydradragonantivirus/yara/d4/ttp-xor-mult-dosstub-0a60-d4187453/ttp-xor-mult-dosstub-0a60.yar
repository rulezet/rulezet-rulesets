rule TTP_XOR_MULT_DOSStub_0a60 {
  strings:
    $key_0a60 = { 5e 08 [2] 2a 10 [2] 6d 12 [2] 2a 03 [2] 64 0f [2] 68 05 [2] 7f 0e [2] 64 40 [2] 59 }

  condition:
    any of them
}