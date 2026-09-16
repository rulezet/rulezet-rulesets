rule TTP_XOR_MULT_DOSStub_592b {
  strings:
    $key_592b = { 0d 43 [2] 79 5b [2] 3e 59 [2] 79 48 [2] 37 44 [2] 3b 4e [2] 2c 45 [2] 37 0b [2] 0a }

  condition:
    any of them
}