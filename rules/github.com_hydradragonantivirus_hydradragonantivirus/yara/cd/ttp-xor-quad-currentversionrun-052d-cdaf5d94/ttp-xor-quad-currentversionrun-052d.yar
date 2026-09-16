rule TTP_XOR_QUAD_CurrentVersionRun_052d {
  strings:
    $key_052d = { 56 42 [2] 72 4c [2] 59 60 [2] 77 42 [2] 63 59 [2] 6c 43 [2] 72 5e [2] 70 5f [2] 6b 59 [2] 77 5e [2] 6b 71 }

  condition:
    any of them
}