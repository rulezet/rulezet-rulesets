rule TTP_XOR_MULT_DOSStub_3f67 {
  strings:
    $key_3f67 = { 6b 0f [2] 1f 17 [2] 58 15 [2] 1f 04 [2] 51 08 [2] 5d 02 [2] 4a 09 [2] 51 47 [2] 6c }

  condition:
    any of them
}