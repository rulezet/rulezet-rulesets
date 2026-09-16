rule TTP_XOR_MULT_DOSStub_24fc {
  strings:
    $key_24fc = { 70 94 [2] 04 8c [2] 43 8e [2] 04 9f [2] 4a 93 [2] 46 99 [2] 51 92 [2] 4a dc [2] 77 }

  condition:
    any of them
}