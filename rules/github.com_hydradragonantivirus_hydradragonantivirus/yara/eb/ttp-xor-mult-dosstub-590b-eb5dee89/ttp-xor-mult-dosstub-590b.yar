rule TTP_XOR_MULT_DOSStub_590b {
  strings:
    $key_590b = { 0d 63 [2] 79 7b [2] 3e 79 [2] 79 68 [2] 37 64 [2] 3b 6e [2] 2c 65 [2] 37 2b [2] 0a }

  condition:
    any of them
}