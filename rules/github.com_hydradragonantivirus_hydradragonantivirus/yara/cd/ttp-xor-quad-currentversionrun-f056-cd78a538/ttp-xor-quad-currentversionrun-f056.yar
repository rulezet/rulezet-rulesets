rule TTP_XOR_QUAD_CurrentVersionRun_f056 {
  strings:
    $key_f056 = { a3 39 [2] 87 37 [2] ac 1b [2] 82 39 [2] 96 22 [2] 99 38 [2] 87 25 [2] 85 24 [2] 9e 22 [2] 82 25 [2] 9e 0a }

  condition:
    any of them
}