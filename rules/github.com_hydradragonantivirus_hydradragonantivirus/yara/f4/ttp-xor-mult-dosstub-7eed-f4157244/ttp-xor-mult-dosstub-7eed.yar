rule TTP_XOR_MULT_DOSStub_7eed {
  strings:
    $key_7eed = { 2a 85 [2] 5e 9d [2] 19 9f [2] 5e 8e [2] 10 82 [2] 1c 88 [2] 0b 83 [2] 10 cd [2] 2d }

  condition:
    any of them
}