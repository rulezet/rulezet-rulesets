rule TTP_XOR_MULT_DOSStub_5f6c {
  strings:
    $key_5f6c = { 0b 04 [2] 7f 1c [2] 38 1e [2] 7f 0f [2] 31 03 [2] 3d 09 [2] 2a 02 [2] 31 4c [2] 0c }

  condition:
    any of them
}