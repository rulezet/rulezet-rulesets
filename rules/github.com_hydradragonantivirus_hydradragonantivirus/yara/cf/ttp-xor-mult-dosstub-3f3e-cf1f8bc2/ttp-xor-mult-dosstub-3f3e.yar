rule TTP_XOR_MULT_DOSStub_3f3e {
  strings:
    $key_3f3e = { 6b 56 [2] 1f 4e [2] 58 4c [2] 1f 5d [2] 51 51 [2] 5d 5b [2] 4a 50 [2] 51 1e [2] 6c }

  condition:
    any of them
}