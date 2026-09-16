rule Crypton_kp__32_big_16_ {
  strings:
    $a0 = { bb 67 ae 85 3c 6e f3 72 a5 4f f5 3a 51 0e 52 7f }

  condition:
    $a0
}