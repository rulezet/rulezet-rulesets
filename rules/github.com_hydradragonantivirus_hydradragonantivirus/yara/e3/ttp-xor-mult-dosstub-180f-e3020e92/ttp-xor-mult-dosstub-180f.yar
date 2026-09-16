rule TTP_XOR_MULT_DOSStub_180f {
  strings:
    $key_180f = { 4c 67 [2] 38 7f [2] 7f 7d [2] 38 6c [2] 76 60 [2] 7a 6a [2] 6d 61 [2] 76 2f [2] 4b }

  condition:
    any of them
}