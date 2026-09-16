rule Dolby_window_dolby_win_32__flt64___64_lil_256_ {
  strings:
    $a0 = { b8 6f 9b e5 28 f6 16 3f a3 58 27 c6 a8 8b 4e 3f 00 e6 1c 13 ec 4e 6a 3f 0e 66 9d 61 40 97 80 3f 03 98 50 1c f6 88 91 3f 37 90 eb 3c c0 6b a0 3f ee db f4 dd c7 12 ac 3f 28 04 17 8d 8e 4e b6 3f fd 4d de 60 6b ad c0 3f 27 4b 37 3a a8 aa c7 3f ab 4a 0f 08 19 0a d0 3f 44 74 01 bf 9d de d4 3f 07 10 4b cb ef 2b da 3f 3c ed 14 61 81 bd df 3f 8e 2b 32 df 29 ab e2 3f 22 91 65 7d d5 5b e5 3f f4 cb 5b bf 22 d4 e7 3f 6a 46 38 68 74 fd e9 3f 1d eb 25 65 92 c9 eb 3f e1 71 9d 83 bb 33 ed 3f ac 43 40 e0 38 40 ee 3f be 89 12 87 90 fa ee 3f 7d 8d d2 47 c1 72 ef 3f 40 74 85 14 2b ba ef 3f 29 b0 bf 4a d7 e0 ef 3f 2b 47 20 2c ad f3 ef 3f a5 e3 6d 23 c9 fb ef 3f 2d 64 44 80 cc fe ef 3f 39 b4 5b 2f bb ff ef 3f d2 09 7d 2f f5 ff ef 3f e3 0c be 16 ff ff ef 3f 46 c4 f0 fd ff ff ef 3f }

  condition:
    $a0
}