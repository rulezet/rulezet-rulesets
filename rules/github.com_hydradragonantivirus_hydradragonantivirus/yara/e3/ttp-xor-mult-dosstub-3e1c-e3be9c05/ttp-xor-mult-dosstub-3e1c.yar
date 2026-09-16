rule TTP_XOR_MULT_DOSStub_3e1c {
  strings:
    $key_3e1c = { 6a 74 [2] 1e 6c [2] 59 6e [2] 1e 7f [2] 50 73 [2] 5c 79 [2] 4b 72 [2] 50 3c [2] 6d }

  condition:
    any of them
}