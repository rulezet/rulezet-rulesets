rule TTP_XOR_MULT_DOSStub_7a6c {
  strings:
    $key_7a6c = { 2e 04 [2] 5a 1c [2] 1d 1e [2] 5a 0f [2] 14 03 [2] 18 09 [2] 0f 02 [2] 14 4c [2] 29 }

  condition:
    any of them
}