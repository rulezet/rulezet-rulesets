rule TTP_XOR_MULT_DOSStub_6fed {
  strings:
    $key_6fed = { 3b 85 [2] 4f 9d [2] 08 9f [2] 4f 8e [2] 01 82 [2] 0d 88 [2] 1a 83 [2] 01 cd [2] 3c }

  condition:
    any of them
}