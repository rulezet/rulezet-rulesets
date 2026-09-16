rule TTP_XOR_MULT_DOSStub_05e3 {
  strings:
    $key_05e3 = { 51 8b [2] 25 93 [2] 62 91 [2] 25 80 [2] 6b 8c [2] 67 86 [2] 70 8d [2] 6b c3 [2] 56 }

  condition:
    any of them
}