rule TTP_XOR_QUAD_CurrentVersionRun_f0d9 {
  strings:
    $key_f0d9 = { a3 b6 [2] 87 b8 [2] ac 94 [2] 82 b6 [2] 96 ad [2] 99 b7 [2] 87 aa [2] 85 ab [2] 9e ad [2] 82 aa [2] 9e 85 }

  condition:
    any of them
}