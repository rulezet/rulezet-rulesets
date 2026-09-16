rule TTP_XOR_MULT_DOSStub_e873 {
  strings:
    $key_e873 = { bc 1b [2] c8 03 [2] 8f 01 [2] c8 10 [2] 86 1c [2] 8a 16 [2] 9d 1d [2] 86 53 [2] bb }

  condition:
    any of them
}