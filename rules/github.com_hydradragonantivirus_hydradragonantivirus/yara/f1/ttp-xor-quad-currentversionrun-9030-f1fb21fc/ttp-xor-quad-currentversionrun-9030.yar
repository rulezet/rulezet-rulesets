rule TTP_XOR_QUAD_CurrentVersionRun_9030 {
  strings:
    $key_9030 = { c3 5f [2] e7 51 [2] cc 7d [2] e2 5f [2] f6 44 [2] f9 5e [2] e7 43 [2] e5 42 [2] fe 44 [2] e2 43 [2] fe 6c }

  condition:
    any of them
}