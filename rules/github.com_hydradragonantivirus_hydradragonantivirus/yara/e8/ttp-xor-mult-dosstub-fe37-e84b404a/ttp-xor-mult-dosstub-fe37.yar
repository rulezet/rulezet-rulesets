rule TTP_XOR_MULT_DOSStub_fe37 {
  strings:
    $key_fe37 = { aa 5f [2] de 47 [2] 99 45 [2] de 54 [2] 90 58 [2] 9c 52 [2] 8b 59 [2] 90 17 [2] ad }

  condition:
    any of them
}