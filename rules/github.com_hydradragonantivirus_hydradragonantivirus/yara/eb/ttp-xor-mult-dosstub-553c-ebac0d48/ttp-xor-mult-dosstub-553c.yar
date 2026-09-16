rule TTP_XOR_MULT_DOSStub_553c {
  strings:
    $key_553c = { 01 54 [2] 75 4c [2] 32 4e [2] 75 5f [2] 3b 53 [2] 37 59 [2] 20 52 [2] 3b 1c [2] 06 }

  condition:
    any of them
}