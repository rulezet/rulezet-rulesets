rule TTP_XOR_QUAD_CurrentVersionRun_270f {
  strings:
    $key_270f = { 74 60 [2] 50 6e [2] 7b 42 [2] 55 60 [2] 41 7b [2] 4e 61 [2] 50 7c [2] 52 7d [2] 49 7b [2] 55 7c [2] 49 53 }

  condition:
    any of them
}