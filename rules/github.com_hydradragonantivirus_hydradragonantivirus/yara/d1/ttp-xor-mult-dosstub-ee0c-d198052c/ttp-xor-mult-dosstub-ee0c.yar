rule TTP_XOR_MULT_DOSStub_ee0c {
  strings:
    $key_ee0c = { ba 64 [2] ce 7c [2] 89 7e [2] ce 6f [2] 80 63 [2] 8c 69 [2] 9b 62 [2] 80 2c [2] bd }

  condition:
    any of them
}