rule TTP_XOR_QUAD_CurrentVersionRun_fe09 {
  strings:
    $key_fe09 = { ad 66 [2] 89 68 [2] a2 44 [2] 8c 66 [2] 98 7d [2] 97 67 [2] 89 7a [2] 8b 7b [2] 90 7d [2] 8c 7a [2] 90 55 }

  condition:
    any of them
}