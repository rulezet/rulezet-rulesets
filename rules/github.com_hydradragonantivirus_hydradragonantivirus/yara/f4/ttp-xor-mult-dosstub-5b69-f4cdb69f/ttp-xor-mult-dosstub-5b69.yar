rule TTP_XOR_MULT_DOSStub_5b69 {
  strings:
    $key_5b69 = { 0f 01 [2] 7b 19 [2] 3c 1b [2] 7b 0a [2] 35 06 [2] 39 0c [2] 2e 07 [2] 35 49 [2] 08 }

  condition:
    any of them
}