rule TTP_XOR_MULT_DOSStub_db07 {
  strings:
    $key_db07 = { 8f 6f [2] fb 77 [2] bc 75 [2] fb 64 [2] b5 68 [2] b9 62 [2] ae 69 [2] b5 27 [2] 88 }

  condition:
    any of them
}