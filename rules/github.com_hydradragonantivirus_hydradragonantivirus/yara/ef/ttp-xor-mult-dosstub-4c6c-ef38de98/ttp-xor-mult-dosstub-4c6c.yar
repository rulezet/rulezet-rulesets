rule TTP_XOR_MULT_DOSStub_4c6c {
  strings:
    $key_4c6c = { 18 04 [2] 6c 1c [2] 2b 1e [2] 6c 0f [2] 22 03 [2] 2e 09 [2] 39 02 [2] 22 4c [2] 1f }

  condition:
    any of them
}