rule TTP_XOR_MULT_DOSStub_1fed {
  strings:
    $key_1fed = { 4b 85 [2] 3f 9d [2] 78 9f [2] 3f 8e [2] 71 82 [2] 7d 88 [2] 6a 83 [2] 71 cd [2] 4c }

  condition:
    any of them
}