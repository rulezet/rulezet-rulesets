rule TTP_XOR_MULT_DOSStub_ffcd {
  strings:
    $key_ffcd = { ab a5 [2] df bd [2] 98 bf [2] df ae [2] 91 a2 [2] 9d a8 [2] 8a a3 [2] 91 ed [2] ac }

  condition:
    any of them
}