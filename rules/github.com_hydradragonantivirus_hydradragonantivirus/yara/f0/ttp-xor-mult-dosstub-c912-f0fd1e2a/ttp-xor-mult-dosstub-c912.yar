rule TTP_XOR_MULT_DOSStub_c912 {
  strings:
    $key_c912 = { 9d 7a [2] e9 62 [2] ae 60 [2] e9 71 [2] a7 7d [2] ab 77 [2] bc 7c [2] a7 32 [2] 9a }

  condition:
    any of them
}