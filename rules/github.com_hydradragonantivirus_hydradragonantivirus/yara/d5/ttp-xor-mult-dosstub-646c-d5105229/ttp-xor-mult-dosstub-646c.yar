rule TTP_XOR_MULT_DOSStub_646c {
  strings:
    $key_646c = { 30 04 [2] 44 1c [2] 03 1e [2] 44 0f [2] 0a 03 [2] 06 09 [2] 11 02 [2] 0a 4c [2] 37 }

  condition:
    any of them
}