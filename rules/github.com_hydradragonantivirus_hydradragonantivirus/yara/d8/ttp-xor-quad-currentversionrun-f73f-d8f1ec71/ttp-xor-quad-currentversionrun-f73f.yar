rule TTP_XOR_QUAD_CurrentVersionRun_f73f {
  strings:
    $key_f73f = { a4 50 [2] 80 5e [2] ab 72 [2] 85 50 [2] 91 4b [2] 9e 51 [2] 80 4c [2] 82 4d [2] 99 4b [2] 85 4c [2] 99 63 }

  condition:
    any of them
}