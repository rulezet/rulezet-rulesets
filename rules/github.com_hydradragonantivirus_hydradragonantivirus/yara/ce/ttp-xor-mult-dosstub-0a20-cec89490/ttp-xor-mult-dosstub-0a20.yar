rule TTP_XOR_MULT_DOSStub_0a20 {
  strings:
    $key_0a20 = { 5e 48 [2] 2a 50 [2] 6d 52 [2] 2a 43 [2] 64 4f [2] 68 45 [2] 7f 4e [2] 64 00 [2] 59 }

  condition:
    any of them
}