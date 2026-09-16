rule TTP_XOR_QUAD_CurrentVersionRun_3c09 {
  strings:
    $key_3c09 = { 6f 66 [2] 4b 68 [2] 60 44 [2] 4e 66 [2] 5a 7d [2] 55 67 [2] 4b 7a [2] 49 7b [2] 52 7d [2] 4e 7a [2] 52 55 }

  condition:
    any of them
}