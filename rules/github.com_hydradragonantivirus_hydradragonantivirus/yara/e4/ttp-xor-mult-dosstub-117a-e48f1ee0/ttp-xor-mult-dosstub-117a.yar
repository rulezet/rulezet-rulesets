rule TTP_XOR_MULT_DOSStub_117a {
  strings:
    $key_117a = { 45 12 [2] 31 0a [2] 76 08 [2] 31 19 [2] 7f 15 [2] 73 1f [2] 64 14 [2] 7f 5a [2] 42 }

  condition:
    any of them
}