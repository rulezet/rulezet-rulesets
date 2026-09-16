rule Erlang__32_big_AND_ {
  strings:
    $a0 = { 9e 37 79 b9 [0-20] 3c 6e f3 72 [0-20] da a6 6d 2b [0-20] 78 dd e6 e4 [0-20] 17 15 60 9d [0-20] b5 4c da 56 [0-20] 53 84 54 0f [0-20] f1 bb cd c8 [0-20] 8f f3 47 81 [0-20] 2e 2a c1 3a [0-20] cc 62 3a f3 [0-20] 6a 99 b4 ac [0-20] 08 d1 2e 65 [0-20] a7 08 a8 1e [0-20] 45 40 21 d7 }

  condition:
    $a0
}