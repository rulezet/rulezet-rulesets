rule TTP_XOR_QUAD_CurrentVersionRun_ffe9 {
  strings:
    $key_ffe9 = { ac 86 [2] 88 88 [2] a3 a4 [2] 8d 86 [2] 99 9d [2] 96 87 [2] 88 9a [2] 8a 9b [2] 91 9d [2] 8d 9a [2] 91 b5 }

  condition:
    any of them
}