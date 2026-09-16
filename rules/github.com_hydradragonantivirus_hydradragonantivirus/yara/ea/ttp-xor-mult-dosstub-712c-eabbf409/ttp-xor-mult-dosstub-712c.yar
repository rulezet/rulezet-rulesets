rule TTP_XOR_MULT_DOSStub_712c {
  strings:
    $key_712c = { 25 44 [2] 51 5c [2] 16 5e [2] 51 4f [2] 1f 43 [2] 13 49 [2] 04 42 [2] 1f 0c [2] 22 }

  condition:
    any of them
}