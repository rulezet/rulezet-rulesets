rule TTP_XOR_MULT_DOSStub_bced {
  strings:
    $key_bced = { e8 85 [2] 9c 9d [2] db 9f [2] 9c 8e [2] d2 82 [2] de 88 [2] c9 83 [2] d2 cd [2] ef }

  condition:
    any of them
}