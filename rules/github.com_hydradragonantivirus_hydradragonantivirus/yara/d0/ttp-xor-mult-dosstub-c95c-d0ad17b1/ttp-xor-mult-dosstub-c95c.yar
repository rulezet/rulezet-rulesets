rule TTP_XOR_MULT_DOSStub_c95c {
  strings:
    $key_c95c = { 9d 34 [2] e9 2c [2] ae 2e [2] e9 3f [2] a7 33 [2] ab 39 [2] bc 32 [2] a7 7c [2] 9a }

  condition:
    any of them
}