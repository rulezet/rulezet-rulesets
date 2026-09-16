rule TTP_XOR_MULT_DOSStub_c973 {
  strings:
    $key_c973 = { 9d 1b [2] e9 03 [2] ae 01 [2] e9 10 [2] a7 1c [2] ab 16 [2] bc 1d [2] a7 53 [2] 9a }

  condition:
    any of them
}