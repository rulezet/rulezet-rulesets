rule TTP_XOR_MULT_DOSStub_e828 {
  strings:
    $key_e828 = { bc 40 [2] c8 58 [2] 8f 5a [2] c8 4b [2] 86 47 [2] 8a 4d [2] 9d 46 [2] 86 08 [2] bb }

  condition:
    any of them
}