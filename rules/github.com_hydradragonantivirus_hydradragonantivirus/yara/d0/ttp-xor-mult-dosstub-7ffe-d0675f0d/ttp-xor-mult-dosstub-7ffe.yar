rule TTP_XOR_MULT_DOSStub_7ffe {
  strings:
    $key_7ffe = { 2b 96 [2] 5f 8e [2] 18 8c [2] 5f 9d [2] 11 91 [2] 1d 9b [2] 0a 90 [2] 11 de [2] 2c }

  condition:
    any of them
}