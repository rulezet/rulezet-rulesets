rule TTP_XOR_MULT_DOSStub_033c {
  strings:
    $key_033c = { 57 54 [2] 23 4c [2] 64 4e [2] 23 5f [2] 6d 53 [2] 61 59 [2] 76 52 [2] 6d 1c [2] 50 }

  condition:
    any of them
}