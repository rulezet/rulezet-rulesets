rule TTP_XOR_MULT_DOSStub_387c {
  strings:
    $key_387c = { 6c 14 [2] 18 0c [2] 5f 0e [2] 18 1f [2] 56 13 [2] 5a 19 [2] 4d 12 [2] 56 5c [2] 6b }

  condition:
    any of them
}