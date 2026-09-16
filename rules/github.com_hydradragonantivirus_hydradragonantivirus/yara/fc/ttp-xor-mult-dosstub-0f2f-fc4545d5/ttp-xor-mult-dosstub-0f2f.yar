rule TTP_XOR_MULT_DOSStub_0f2f {
  strings:
    $key_0f2f = { 5b 47 [2] 2f 5f [2] 68 5d [2] 2f 4c [2] 61 40 [2] 6d 4a [2] 7a 41 [2] 61 0f [2] 5c }

  condition:
    any of them
}