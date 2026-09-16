rule TTP_XOR_QUAD_CurrentVersionRun_3ae8 {
  strings:
    $key_3ae8 = { 69 87 [2] 4d 89 [2] 66 a5 [2] 48 87 [2] 5c 9c [2] 53 86 [2] 4d 9b [2] 4f 9a [2] 54 9c [2] 48 9b [2] 54 b4 }

  condition:
    any of them
}