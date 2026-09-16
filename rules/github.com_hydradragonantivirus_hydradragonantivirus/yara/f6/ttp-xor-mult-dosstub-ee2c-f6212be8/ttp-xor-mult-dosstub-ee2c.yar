rule TTP_XOR_MULT_DOSStub_ee2c {
  strings:
    $key_ee2c = { ba 44 [2] ce 5c [2] 89 5e [2] ce 4f [2] 80 43 [2] 8c 49 [2] 9b 42 [2] 80 0c [2] bd }

  condition:
    any of them
}