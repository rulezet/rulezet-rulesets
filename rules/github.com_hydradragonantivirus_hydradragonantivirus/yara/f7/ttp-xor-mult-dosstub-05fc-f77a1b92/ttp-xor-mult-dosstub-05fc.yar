rule TTP_XOR_MULT_DOSStub_05fc {
  strings:
    $key_05fc = { 51 94 [2] 25 8c [2] 62 8e [2] 25 9f [2] 6b 93 [2] 67 99 [2] 70 92 [2] 6b dc [2] 56 }

  condition:
    any of them
}