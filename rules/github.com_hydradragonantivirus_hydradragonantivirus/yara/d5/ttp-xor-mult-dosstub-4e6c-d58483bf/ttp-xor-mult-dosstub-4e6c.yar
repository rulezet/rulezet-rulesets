rule TTP_XOR_MULT_DOSStub_4e6c {
  strings:
    $key_4e6c = { 1a 04 [2] 6e 1c [2] 29 1e [2] 6e 0f [2] 20 03 [2] 2c 09 [2] 3b 02 [2] 20 4c [2] 1d }

  condition:
    any of them
}