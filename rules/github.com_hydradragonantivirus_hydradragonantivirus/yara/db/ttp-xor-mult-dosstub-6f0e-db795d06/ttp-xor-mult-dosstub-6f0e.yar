rule TTP_XOR_MULT_DOSStub_6f0e {
  strings:
    $key_6f0e = { 3b 66 [2] 4f 7e [2] 08 7c [2] 4f 6d [2] 01 61 [2] 0d 6b [2] 1a 60 [2] 01 2e [2] 3c }

  condition:
    any of them
}