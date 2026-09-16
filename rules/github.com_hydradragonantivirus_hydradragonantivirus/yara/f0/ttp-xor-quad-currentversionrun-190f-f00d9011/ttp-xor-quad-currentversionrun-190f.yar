rule TTP_XOR_QUAD_CurrentVersionRun_190f {
  strings:
    $key_190f = { 4a 60 [2] 6e 6e [2] 45 42 [2] 6b 60 [2] 7f 7b [2] 70 61 [2] 6e 7c [2] 6c 7d [2] 77 7b [2] 6b 7c [2] 77 53 }

  condition:
    any of them
}