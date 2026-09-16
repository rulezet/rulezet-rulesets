rule TTP_XOR_MULT_DOSStub_2f0e {
  strings:
    $key_2f0e = { 7b 66 [2] 0f 7e [2] 48 7c [2] 0f 6d [2] 41 61 [2] 4d 6b [2] 5a 60 [2] 41 2e [2] 7c }

  condition:
    any of them
}