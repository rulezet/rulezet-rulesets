rule TTP_XOR_MULT_DOSStub_0f3c {
  strings:
    $key_0f3c = { 5b 54 [2] 2f 4c [2] 68 4e [2] 2f 5f [2] 61 53 [2] 6d 59 [2] 7a 52 [2] 61 1c [2] 5c }

  condition:
    any of them
}