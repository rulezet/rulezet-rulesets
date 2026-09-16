rule TTP_XOR_QUAD_CurrentVersionRun_0209 {
  strings:
    $key_0209 = { 51 66 [2] 75 68 [2] 5e 44 [2] 70 66 [2] 64 7d [2] 6b 67 [2] 75 7a [2] 77 7b [2] 6c 7d [2] 70 7a [2] 6c 55 }

  condition:
    any of them
}