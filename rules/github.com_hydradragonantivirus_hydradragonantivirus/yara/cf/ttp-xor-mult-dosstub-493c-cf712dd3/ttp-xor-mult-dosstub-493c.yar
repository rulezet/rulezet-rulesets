rule TTP_XOR_MULT_DOSStub_493c {
  strings:
    $key_493c = { 1d 54 [2] 69 4c [2] 2e 4e [2] 69 5f [2] 27 53 [2] 2b 59 [2] 3c 52 [2] 27 1c [2] 1a }

  condition:
    any of them
}