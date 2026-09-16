rule TTP_XOR_QUAD_CurrentVersionRun_f1e9 {
  strings:
    $key_f1e9 = { a2 86 [2] 86 88 [2] ad a4 [2] 83 86 [2] 97 9d [2] 98 87 [2] 86 9a [2] 84 9b [2] 9f 9d [2] 83 9a [2] 9f b5 }

  condition:
    any of them
}