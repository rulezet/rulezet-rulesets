rule TTP_XOR_MULT_DOSStub_db30 {
  strings:
    $key_db30 = { 8f 58 [2] fb 40 [2] bc 42 [2] fb 53 [2] b5 5f [2] b9 55 [2] ae 5e [2] b5 10 [2] 88 }

  condition:
    any of them
}