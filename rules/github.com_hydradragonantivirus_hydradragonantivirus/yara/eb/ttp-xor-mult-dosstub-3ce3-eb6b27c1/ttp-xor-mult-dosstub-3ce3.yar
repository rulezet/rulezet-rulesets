rule TTP_XOR_MULT_DOSStub_3ce3 {
  strings:
    $key_3ce3 = { 68 8b [2] 1c 93 [2] 5b 91 [2] 1c 80 [2] 52 8c [2] 5e 86 [2] 49 8d [2] 52 c3 [2] 6f }

  condition:
    any of them
}