rule TTP_XOR_MULT_DOSStub_7a57 {
  strings:
    $key_7a57 = { 2e 3f [2] 5a 27 [2] 1d 25 [2] 5a 34 [2] 14 38 [2] 18 32 [2] 0f 39 [2] 14 77 [2] 29 }

  condition:
    any of them
}