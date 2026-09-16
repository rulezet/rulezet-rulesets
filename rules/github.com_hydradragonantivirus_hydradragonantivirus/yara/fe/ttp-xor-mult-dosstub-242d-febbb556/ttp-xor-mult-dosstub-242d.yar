rule TTP_XOR_MULT_DOSStub_242d {
  strings:
    $key_242d = { 70 45 [2] 04 5d [2] 43 5f [2] 04 4e [2] 4a 42 [2] 46 48 [2] 51 43 [2] 4a 0d [2] 77 }

  condition:
    any of them
}