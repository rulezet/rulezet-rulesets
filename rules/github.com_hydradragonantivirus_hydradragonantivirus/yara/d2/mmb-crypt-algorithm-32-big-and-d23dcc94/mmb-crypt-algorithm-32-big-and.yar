rule MMB_crypt_algorithm__32_big_AND_ {
  strings:
    $a0 = { 02 5f 1c db [0-20] 04 be 39 b6 [0-20] 12 f8 e6 d8 [0-20] 2f 8e 6d 81 [0-20] 0d ad 46 94 [0-20] 06 d6 a3 4a [0-20] 81 b5 a8 d2 [0-20] 28 1b 5a 8d [0-20] 2a aa aa aa }

  condition:
    $a0
}