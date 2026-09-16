rule TTP_XOR_MULT_DOSStub_651f {
  strings:
    $key_651f = { 31 77 [2] 45 6f [2] 02 6d [2] 45 7c [2] 0b 70 [2] 07 7a [2] 10 71 [2] 0b 3f [2] 36 }

  condition:
    any of them
}