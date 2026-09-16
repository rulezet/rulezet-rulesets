rule TTP_XOR_MULT_DOSStub_5929 {
  strings:
    $key_5929 = { 0d 41 [2] 79 59 [2] 3e 5b [2] 79 4a [2] 37 46 [2] 3b 4c [2] 2c 47 [2] 37 09 [2] 0a }

  condition:
    any of them
}