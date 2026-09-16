rule TTP_XOR_MULT_DOSStub_c926 {
  strings:
    $key_c926 = { 9d 4e [2] e9 56 [2] ae 54 [2] e9 45 [2] a7 49 [2] ab 43 [2] bc 48 [2] a7 06 [2] 9a }

  condition:
    any of them
}