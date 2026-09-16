rule TTP_XOR_QUAD_CurrentVersionRun_fff9 {
  strings:
    $key_fff9 = { ac 96 [2] 88 98 [2] a3 b4 [2] 8d 96 [2] 99 8d [2] 96 97 [2] 88 8a [2] 8a 8b [2] 91 8d [2] 8d 8a [2] 91 a5 }

  condition:
    any of them
}