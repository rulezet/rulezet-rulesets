rule TTP_XOR_QUAD_CurrentVersionRun_f0c4 {
  strings:
    $key_f0c4 = { a3 ab [2] 87 a5 [2] ac 89 [2] 82 ab [2] 96 b0 [2] 99 aa [2] 87 b7 [2] 85 b6 [2] 9e b0 [2] 82 b7 [2] 9e 98 }

  condition:
    any of them
}