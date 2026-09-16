rule TTP_XOR_MULT_DOSStub_306c {
  strings:
    $key_306c = { 64 04 [2] 10 1c [2] 57 1e [2] 10 0f [2] 5e 03 [2] 52 09 [2] 45 02 [2] 5e 4c [2] 63 }

  condition:
    any of them
}