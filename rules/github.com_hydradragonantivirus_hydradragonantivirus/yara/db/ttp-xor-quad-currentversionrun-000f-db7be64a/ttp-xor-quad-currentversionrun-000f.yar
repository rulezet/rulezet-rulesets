rule TTP_XOR_QUAD_CurrentVersionRun_000f {
  strings:
    $key_000f = { 53 60 [2] 77 6e [2] 5c 42 [2] 72 60 [2] 66 7b [2] 69 61 [2] 77 7c [2] 75 7d [2] 6e 7b [2] 72 7c [2] 6e 53 }

  condition:
    any of them
}