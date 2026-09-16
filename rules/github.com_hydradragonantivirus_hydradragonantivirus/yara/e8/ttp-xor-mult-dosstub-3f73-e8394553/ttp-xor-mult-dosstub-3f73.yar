rule TTP_XOR_MULT_DOSStub_3f73 {
  strings:
    $key_3f73 = { 6b 1b [2] 1f 03 [2] 58 01 [2] 1f 10 [2] 51 1c [2] 5d 16 [2] 4a 1d [2] 51 53 [2] 6c }

  condition:
    any of them
}