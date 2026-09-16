rule TTP_XOR_QUAD_CurrentVersionRun_2ee9 {
  strings:
    $key_2ee9 = { 7d 86 [2] 59 88 [2] 72 a4 [2] 5c 86 [2] 48 9d [2] 47 87 [2] 59 9a [2] 5b 9b [2] 40 9d [2] 5c 9a [2] 40 b5 }

  condition:
    any of them
}