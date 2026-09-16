rule TTP_XOR_MULT_DOSStub_2fea {
  strings:
    $key_2fea = { 7b 82 [2] 0f 9a [2] 48 98 [2] 0f 89 [2] 41 85 [2] 4d 8f [2] 5a 84 [2] 41 ca [2] 7c }

  condition:
    any of them
}