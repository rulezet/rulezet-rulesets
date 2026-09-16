rule TTP_XOR_MULT_DOSStub_570f {
  strings:
    $key_570f = { 03 67 [2] 77 7f [2] 30 7d [2] 77 6c [2] 39 60 [2] 35 6a [2] 22 61 [2] 39 2f [2] 04 }

  condition:
    any of them
}