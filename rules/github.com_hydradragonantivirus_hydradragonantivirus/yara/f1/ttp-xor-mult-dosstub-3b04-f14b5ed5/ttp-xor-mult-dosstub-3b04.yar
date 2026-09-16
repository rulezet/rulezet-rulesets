rule TTP_XOR_MULT_DOSStub_3b04 {
  strings:
    $key_3b04 = { 6f 6c [2] 1b 74 [2] 5c 76 [2] 1b 67 [2] 55 6b [2] 59 61 [2] 4e 6a [2] 55 24 [2] 68 }

  condition:
    any of them
}