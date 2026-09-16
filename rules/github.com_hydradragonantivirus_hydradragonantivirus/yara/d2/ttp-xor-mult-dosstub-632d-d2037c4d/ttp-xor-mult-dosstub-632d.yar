rule TTP_XOR_MULT_DOSStub_632d {
  strings:
    $key_632d = { 37 45 [2] 43 5d [2] 04 5f [2] 43 4e [2] 0d 42 [2] 01 48 [2] 16 43 [2] 0d 0d [2] 30 }

  condition:
    any of them
}