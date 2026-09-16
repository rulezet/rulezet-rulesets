rule TTP_XOR_MULT_DOSStub_4539 {
  strings:
    $key_4539 = { 11 51 [2] 65 49 [2] 22 4b [2] 65 5a [2] 2b 56 [2] 27 5c [2] 30 57 [2] 2b 19 [2] 16 }

  condition:
    any of them
}