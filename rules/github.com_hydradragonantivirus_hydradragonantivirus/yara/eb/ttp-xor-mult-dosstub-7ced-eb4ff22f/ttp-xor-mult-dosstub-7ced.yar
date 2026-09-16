rule TTP_XOR_MULT_DOSStub_7ced {
  strings:
    $key_7ced = { 28 85 [2] 5c 9d [2] 1b 9f [2] 5c 8e [2] 12 82 [2] 1e 88 [2] 09 83 [2] 12 cd [2] 2f }

  condition:
    any of them
}