rule TTP_XOR_MULT_DOSStub_746c {
  strings:
    $key_746c = { 20 04 [2] 54 1c [2] 13 1e [2] 54 0f [2] 1a 03 [2] 16 09 [2] 01 02 [2] 1a 4c [2] 27 }

  condition:
    any of them
}