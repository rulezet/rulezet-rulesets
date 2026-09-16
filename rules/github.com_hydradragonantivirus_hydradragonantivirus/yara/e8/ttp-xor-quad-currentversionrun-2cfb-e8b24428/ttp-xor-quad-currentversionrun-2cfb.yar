rule TTP_XOR_QUAD_CurrentVersionRun_2cfb {
  strings:
    $key_2cfb = { 7f 94 [2] 5b 9a [2] 70 b6 [2] 5e 94 [2] 4a 8f [2] 45 95 [2] 5b 88 [2] 59 89 [2] 42 8f [2] 5e 88 [2] 42 a7 }

  condition:
    any of them
}