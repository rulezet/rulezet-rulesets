rule TTP_XOR_MULT_DOSStub_051f {
  strings:
    $key_051f = { 51 77 [2] 25 6f [2] 62 6d [2] 25 7c [2] 6b 70 [2] 67 7a [2] 70 71 [2] 6b 3f [2] 56 }

  condition:
    any of them
}