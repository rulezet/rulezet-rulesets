rule TTP_XOR_MULT_DOSStub_2cf5 {
  strings:
    $key_2cf5 = { 78 9d [2] 0c 85 [2] 4b 87 [2] 0c 96 [2] 42 9a [2] 4e 90 [2] 59 9b [2] 42 d5 [2] 7f }

  condition:
    any of them
}