rule TTP_XOR_MULT_DOSStub_2f73 {
  strings:
    $key_2f73 = { 7b 1b [2] 0f 03 [2] 48 01 [2] 0f 10 [2] 41 1c [2] 4d 16 [2] 5a 1d [2] 41 53 [2] 7c }

  condition:
    any of them
}