rule TTP_XOR_MULT_DOSStub_206c {
  strings:
    $key_206c = { 74 04 [2] 00 1c [2] 47 1e [2] 00 0f [2] 4e 03 [2] 42 09 [2] 55 02 [2] 4e 4c [2] 73 }

  condition:
    any of them
}