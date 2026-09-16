rule TTP_XOR_MULT_DOSStub_6f2e {
  strings:
    $key_6f2e = { 3b 46 [2] 4f 5e [2] 08 5c [2] 4f 4d [2] 01 41 [2] 0d 4b [2] 1a 40 [2] 01 0e [2] 3c }

  condition:
    any of them
}