rule TTP_XOR_MULT_DOSStub_59fd {
  strings:
    $key_59fd = { 0d 95 [2] 79 8d [2] 3e 8f [2] 79 9e [2] 37 92 [2] 3b 98 [2] 2c 93 [2] 37 dd [2] 0a }

  condition:
    any of them
}