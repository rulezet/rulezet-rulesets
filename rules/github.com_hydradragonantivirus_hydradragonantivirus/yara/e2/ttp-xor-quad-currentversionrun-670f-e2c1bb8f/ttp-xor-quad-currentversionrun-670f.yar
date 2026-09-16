rule TTP_XOR_QUAD_CurrentVersionRun_670f {
  strings:
    $key_670f = { 34 60 [2] 10 6e [2] 3b 42 [2] 15 60 [2] 01 7b [2] 0e 61 [2] 10 7c [2] 12 7d [2] 09 7b [2] 15 7c [2] 09 53 }

  condition:
    any of them
}