rule TTP_XOR_MULT_DOSStub_2b3f {
  strings:
    $key_2b3f = { 7f 57 [2] 0b 4f [2] 4c 4d [2] 0b 5c [2] 45 50 [2] 49 5a [2] 5e 51 [2] 45 1f [2] 78 }

  condition:
    any of them
}