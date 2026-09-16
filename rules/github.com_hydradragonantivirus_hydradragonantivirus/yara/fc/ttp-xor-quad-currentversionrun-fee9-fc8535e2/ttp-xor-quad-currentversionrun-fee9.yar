rule TTP_XOR_QUAD_CurrentVersionRun_fee9 {
  strings:
    $key_fee9 = { ad 86 [2] 89 88 [2] a2 a4 [2] 8c 86 [2] 98 9d [2] 97 87 [2] 89 9a [2] 8b 9b [2] 90 9d [2] 8c 9a [2] 90 b5 }

  condition:
    any of them
}