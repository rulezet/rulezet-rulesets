rule TTP_XOR_MULT_DOSStub_2c6c {
  strings:
    $key_2c6c = { 78 04 [2] 0c 1c [2] 4b 1e [2] 0c 0f [2] 42 03 [2] 4e 09 [2] 59 02 [2] 42 4c [2] 7f }

  condition:
    any of them
}