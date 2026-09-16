rule TTP_XOR_MULT_DOSStub_192c {
  strings:
    $key_192c = { 4d 44 [2] 39 5c [2] 7e 5e [2] 39 4f [2] 77 43 [2] 7b 49 [2] 6c 42 [2] 77 0c [2] 4a }

  condition:
    any of them
}