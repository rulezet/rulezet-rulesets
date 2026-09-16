rule TTP_XOR_MULT_DOSStub_302c {
  strings:
    $key_302c = { 64 44 [2] 10 5c [2] 57 5e [2] 10 4f [2] 5e 43 [2] 52 49 [2] 45 42 [2] 5e 0c [2] 63 }

  condition:
    any of them
}