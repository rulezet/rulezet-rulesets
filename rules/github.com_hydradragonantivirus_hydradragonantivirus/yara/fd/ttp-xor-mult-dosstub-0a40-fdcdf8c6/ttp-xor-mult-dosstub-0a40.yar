rule TTP_XOR_MULT_DOSStub_0a40 {
  strings:
    $key_0a40 = { 5e 28 [2] 2a 30 [2] 6d 32 [2] 2a 23 [2] 64 2f [2] 68 25 [2] 7f 2e [2] 64 60 [2] 59 }

  condition:
    any of them
}