rule TTP_XOR_MULT_DOSStub_6a3e {
  strings:
    $key_6a3e = { 3e 56 [2] 4a 4e [2] 0d 4c [2] 4a 5d [2] 04 51 [2] 08 5b [2] 1f 50 [2] 04 1e [2] 39 }

  condition:
    any of them
}