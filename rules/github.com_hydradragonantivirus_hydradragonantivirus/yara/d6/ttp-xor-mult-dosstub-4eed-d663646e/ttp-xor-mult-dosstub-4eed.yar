rule TTP_XOR_MULT_DOSStub_4eed {
  strings:
    $key_4eed = { 1a 85 [2] 6e 9d [2] 29 9f [2] 6e 8e [2] 20 82 [2] 2c 88 [2] 3b 83 [2] 20 cd [2] 1d }

  condition:
    any of them
}