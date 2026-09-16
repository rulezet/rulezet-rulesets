rule TTP_XOR_QUAD_CurrentVersionRun_f20f {
  strings:
    $key_f20f = { a1 60 [2] 85 6e [2] ae 42 [2] 80 60 [2] 94 7b [2] 9b 61 [2] 85 7c [2] 87 7d [2] 9c 7b [2] 80 7c [2] 9c 53 }

  condition:
    any of them
}