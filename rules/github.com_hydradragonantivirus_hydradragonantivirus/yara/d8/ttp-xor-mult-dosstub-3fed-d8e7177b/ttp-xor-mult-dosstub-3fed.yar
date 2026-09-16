rule TTP_XOR_MULT_DOSStub_3fed {
  strings:
    $key_3fed = { 6b 85 [2] 1f 9d [2] 58 9f [2] 1f 8e [2] 51 82 [2] 5d 88 [2] 4a 83 [2] 51 cd [2] 6c }

  condition:
    any of them
}