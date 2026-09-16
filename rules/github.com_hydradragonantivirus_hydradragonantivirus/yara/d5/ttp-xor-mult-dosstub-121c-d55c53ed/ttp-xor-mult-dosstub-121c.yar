rule TTP_XOR_MULT_DOSStub_121c {
  strings:
    $key_121c = { 46 74 [2] 32 6c [2] 75 6e [2] 32 7f [2] 7c 73 [2] 70 79 [2] 67 72 [2] 7c 3c [2] 41 }

  condition:
    any of them
}