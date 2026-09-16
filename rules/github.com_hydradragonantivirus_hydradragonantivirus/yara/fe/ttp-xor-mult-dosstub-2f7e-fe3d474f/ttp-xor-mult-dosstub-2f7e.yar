rule TTP_XOR_MULT_DOSStub_2f7e {
  strings:
    $key_2f7e = { 7b 16 [2] 0f 0e [2] 48 0c [2] 0f 1d [2] 41 11 [2] 4d 1b [2] 5a 10 [2] 41 5e [2] 7c }

  condition:
    any of them
}