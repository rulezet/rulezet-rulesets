rule TTP_XOR_MULT_DOSStub_3e7c {
  strings:
    $key_3e7c = { 6a 14 [2] 1e 0c [2] 59 0e [2] 1e 1f [2] 50 13 [2] 5c 19 [2] 4b 12 [2] 50 5c [2] 6d }

  condition:
    any of them
}