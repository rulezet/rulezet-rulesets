rule TTP_XOR_MULT_DOSStub_6a57 {
  strings:
    $key_6a57 = { 3e 3f [2] 4a 27 [2] 0d 25 [2] 4a 34 [2] 04 38 [2] 08 32 [2] 1f 39 [2] 04 77 [2] 39 }

  condition:
    any of them
}