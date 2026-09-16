rule TTP_XOR_MULT_DOSStub_630f {
  strings:
    $key_630f = { 37 67 [2] 43 7f [2] 04 7d [2] 43 6c [2] 0d 60 [2] 01 6a [2] 16 61 [2] 0d 2f [2] 30 }

  condition:
    any of them
}