rule TTP_XOR_MULT_DOSStub_a57a {
  strings:
    $key_a57a = { f1 12 [2] 85 0a [2] c2 08 [2] 85 19 [2] cb 15 [2] c7 1f [2] d0 14 [2] cb 5a [2] f6 }

  condition:
    any of them
}