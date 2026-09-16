rule TTP_XOR_QUAD_CurrentVersionRun_3ce9 {
  strings:
    $key_3ce9 = { 6f 86 [2] 4b 88 [2] 60 a4 [2] 4e 86 [2] 5a 9d [2] 55 87 [2] 4b 9a [2] 49 9b [2] 52 9d [2] 4e 9a [2] 52 b5 }

  condition:
    any of them
}