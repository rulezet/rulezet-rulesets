rule TTP_XOR_MULT_DOSStub_246c {
  strings:
    $key_246c = { 70 04 [2] 04 1c [2] 43 1e [2] 04 0f [2] 4a 03 [2] 46 09 [2] 51 02 [2] 4a 4c [2] 77 }

  condition:
    any of them
}