rule LZ_Huffman__lzhuf_lha__encoding_table__8_byt_64_ {
  strings:
    $a0 = { 00 20 30 40 50 58 60 68 70 78 80 88 90 94 98 9c a0 a4 a8 ac b0 b4 b8 bc c0 c2 c4 c6 c8 ca cc ce d0 d2 d4 d6 d8 da dc de e0 e2 e4 e6 e8 ea ec ee f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff }

  condition:
    $a0
}