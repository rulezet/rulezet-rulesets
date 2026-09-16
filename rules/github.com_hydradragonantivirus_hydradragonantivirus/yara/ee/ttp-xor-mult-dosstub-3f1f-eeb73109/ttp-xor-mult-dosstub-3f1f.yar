rule TTP_XOR_MULT_DOSStub_3f1f {
  strings:
    $key_3f1f = { 6b 77 [2] 1f 6f [2] 58 6d [2] 1f 7c [2] 51 70 [2] 5d 7a [2] 4a 71 [2] 51 3f [2] 6c }

  condition:
    any of them
}