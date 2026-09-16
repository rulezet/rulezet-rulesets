rule TTP_XOR_QUAD_CurrentVersionRun_62e9 {
  strings:
    $key_62e9 = { 31 86 [2] 15 88 [2] 3e a4 [2] 10 86 [2] 04 9d [2] 0b 87 [2] 15 9a [2] 17 9b [2] 0c 9d [2] 10 9a [2] 0c b5 }

  condition:
    any of them
}