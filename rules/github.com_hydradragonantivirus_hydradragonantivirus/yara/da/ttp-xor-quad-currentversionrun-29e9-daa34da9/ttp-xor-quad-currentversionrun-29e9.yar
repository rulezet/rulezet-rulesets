rule TTP_XOR_QUAD_CurrentVersionRun_29e9 {
  strings:
    $key_29e9 = { 7a 86 [2] 5e 88 [2] 75 a4 [2] 5b 86 [2] 4f 9d [2] 40 87 [2] 5e 9a [2] 5c 9b [2] 47 9d [2] 5b 9a [2] 47 b5 }

  condition:
    any of them
}