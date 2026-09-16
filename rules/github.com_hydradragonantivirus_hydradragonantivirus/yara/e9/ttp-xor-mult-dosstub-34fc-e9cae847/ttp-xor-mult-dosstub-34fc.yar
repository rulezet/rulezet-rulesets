rule TTP_XOR_MULT_DOSStub_34fc {
  strings:
    $key_34fc = { 60 94 [2] 14 8c [2] 53 8e [2] 14 9f [2] 5a 93 [2] 56 99 [2] 41 92 [2] 5a dc [2] 67 }

  condition:
    any of them
}