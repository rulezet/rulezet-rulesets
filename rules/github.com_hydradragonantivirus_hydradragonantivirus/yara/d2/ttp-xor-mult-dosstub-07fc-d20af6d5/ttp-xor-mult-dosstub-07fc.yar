rule TTP_XOR_MULT_DOSStub_07fc {
  strings:
    $key_07fc = { 53 94 [2] 27 8c [2] 60 8e [2] 27 9f [2] 69 93 [2] 65 99 [2] 72 92 [2] 69 dc [2] 54 }

  condition:
    any of them
}