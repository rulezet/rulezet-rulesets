rule TTP_XOR_MULT_DOSStub_3731 {
  strings:
    $key_3731 = { 63 59 [2] 17 41 [2] 50 43 [2] 17 52 [2] 59 5e [2] 55 54 [2] 42 5f [2] 59 11 [2] 64 }

  condition:
    any of them
}