rule TTP_XOR_MULT_DOSStub_1f6c {
  strings:
    $key_1f6c = { 4b 04 [2] 3f 1c [2] 78 1e [2] 3f 0f [2] 71 03 [2] 7d 09 [2] 6a 02 [2] 71 4c [2] 4c }

  condition:
    any of them
}