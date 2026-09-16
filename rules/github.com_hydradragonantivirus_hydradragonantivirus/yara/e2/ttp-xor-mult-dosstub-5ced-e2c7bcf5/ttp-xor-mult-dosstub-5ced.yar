rule TTP_XOR_MULT_DOSStub_5ced {
  strings:
    $key_5ced = { 08 85 [2] 7c 9d [2] 3b 9f [2] 7c 8e [2] 32 82 [2] 3e 88 [2] 29 83 [2] 32 cd [2] 0f }

  condition:
    any of them
}