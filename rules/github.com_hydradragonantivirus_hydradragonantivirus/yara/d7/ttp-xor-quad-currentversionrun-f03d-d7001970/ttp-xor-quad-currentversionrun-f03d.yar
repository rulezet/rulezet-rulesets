rule TTP_XOR_QUAD_CurrentVersionRun_f03d {
  strings:
    $key_f03d = { a3 52 [2] 87 5c [2] ac 70 [2] 82 52 [2] 96 49 [2] 99 53 [2] 87 4e [2] 85 4f [2] 9e 49 [2] 82 4e [2] 9e 61 }

  condition:
    any of them
}