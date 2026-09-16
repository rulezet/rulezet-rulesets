rule TTP_XOR_MULT_DOSStub_7fed {
  strings:
    $key_7fed = { 2b 85 [2] 5f 9d [2] 18 9f [2] 5f 8e [2] 11 82 [2] 1d 88 [2] 0a 83 [2] 11 cd [2] 2c }

  condition:
    any of them
}