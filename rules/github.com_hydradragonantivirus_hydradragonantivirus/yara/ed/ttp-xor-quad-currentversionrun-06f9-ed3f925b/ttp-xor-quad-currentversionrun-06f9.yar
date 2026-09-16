rule TTP_XOR_QUAD_CurrentVersionRun_06f9 {
  strings:
    $key_06f9 = { 55 96 [2] 71 98 [2] 5a b4 [2] 74 96 [2] 60 8d [2] 6f 97 [2] 71 8a [2] 73 8b [2] 68 8d [2] 74 8a [2] 68 a5 }

  condition:
    any of them
}