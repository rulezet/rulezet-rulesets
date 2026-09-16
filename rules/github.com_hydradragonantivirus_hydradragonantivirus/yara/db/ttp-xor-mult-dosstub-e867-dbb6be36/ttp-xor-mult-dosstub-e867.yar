rule TTP_XOR_MULT_DOSStub_e867 {
  strings:
    $key_e867 = { bc 0f [2] c8 17 [2] 8f 15 [2] c8 04 [2] 86 08 [2] 8a 02 [2] 9d 09 [2] 86 47 [2] bb }

  condition:
    any of them
}