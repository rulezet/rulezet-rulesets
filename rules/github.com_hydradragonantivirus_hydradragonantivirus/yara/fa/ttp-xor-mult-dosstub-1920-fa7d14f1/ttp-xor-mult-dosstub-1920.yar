rule TTP_XOR_MULT_DOSStub_1920 {
  strings:
    $key_1920 = { 4d 48 [2] 39 50 [2] 7e 52 [2] 39 43 [2] 77 4f [2] 7b 45 [2] 6c 4e [2] 77 00 [2] 4a }

  condition:
    any of them
}