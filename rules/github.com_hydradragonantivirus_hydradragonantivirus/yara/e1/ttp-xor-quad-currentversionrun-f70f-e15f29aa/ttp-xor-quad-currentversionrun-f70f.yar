rule TTP_XOR_QUAD_CurrentVersionRun_f70f {
  strings:
    $key_f70f = { a4 60 [2] 80 6e [2] ab 42 [2] 85 60 [2] 91 7b [2] 9e 61 [2] 80 7c [2] 82 7d [2] 99 7b [2] 85 7c [2] 99 53 }

  condition:
    any of them
}