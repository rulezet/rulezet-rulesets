rule TTP_XOR_MULT_DOSStub_446c {
  strings:
    $key_446c = { 10 04 [2] 64 1c [2] 23 1e [2] 64 0f [2] 2a 03 [2] 26 09 [2] 31 02 [2] 2a 4c [2] 17 }

  condition:
    any of them
}