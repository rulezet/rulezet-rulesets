rule TTP_XOR_QUAD_CurrentVersionRun_a230 {
  strings:
    $key_a230 = { f1 5f [2] d5 51 [2] fe 7d [2] d0 5f [2] c4 44 [2] cb 5e [2] d5 43 [2] d7 42 [2] cc 44 [2] d0 43 [2] cc 6c }

  condition:
    any of them
}