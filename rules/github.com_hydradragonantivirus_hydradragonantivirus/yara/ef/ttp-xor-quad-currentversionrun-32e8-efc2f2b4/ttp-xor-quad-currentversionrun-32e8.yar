rule TTP_XOR_QUAD_CurrentVersionRun_32e8 {
  strings:
    $key_32e8 = { 61 87 [2] 45 89 [2] 6e a5 [2] 40 87 [2] 54 9c [2] 5b 86 [2] 45 9b [2] 47 9a [2] 5c 9c [2] 40 9b [2] 5c b4 }

  condition:
    any of them
}