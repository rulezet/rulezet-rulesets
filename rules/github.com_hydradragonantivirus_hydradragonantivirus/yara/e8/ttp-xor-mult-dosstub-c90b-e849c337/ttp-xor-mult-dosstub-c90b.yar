rule TTP_XOR_MULT_DOSStub_c90b {
  strings:
    $key_c90b = { 9d 63 [2] e9 7b [2] ae 79 [2] e9 68 [2] a7 64 [2] ab 6e [2] bc 65 [2] a7 2b [2] 9a }

  condition:
    any of them
}