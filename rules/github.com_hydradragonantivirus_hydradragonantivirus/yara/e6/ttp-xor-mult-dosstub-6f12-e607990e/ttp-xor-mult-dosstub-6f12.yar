rule TTP_XOR_MULT_DOSStub_6f12 {
  strings:
    $key_6f12 = { 3b 7a [2] 4f 62 [2] 08 60 [2] 4f 71 [2] 01 7d [2] 0d 77 [2] 1a 7c [2] 01 32 [2] 3c }

  condition:
    any of them
}