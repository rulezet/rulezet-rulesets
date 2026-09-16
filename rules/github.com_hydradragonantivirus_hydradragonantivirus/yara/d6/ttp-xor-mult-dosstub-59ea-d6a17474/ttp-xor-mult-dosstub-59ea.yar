rule TTP_XOR_MULT_DOSStub_59ea {
  strings:
    $key_59ea = { 0d 82 [2] 79 9a [2] 3e 98 [2] 79 89 [2] 37 85 [2] 3b 8f [2] 2c 84 [2] 37 ca [2] 0a }

  condition:
    any of them
}