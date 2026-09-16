rule TTP_XOR_MULT_DOSStub_7e3e {
  strings:
    $key_7e3e = { 2a 56 [2] 5e 4e [2] 19 4c [2] 5e 5d [2] 10 51 [2] 1c 5b [2] 0b 50 [2] 10 1e [2] 2d }

  condition:
    any of them
}