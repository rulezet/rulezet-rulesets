rule TTP_XOR_QUAD_CurrentVersionRun_e430 {
  strings:
    $key_e430 = { b7 5f [2] 93 51 [2] b8 7d [2] 96 5f [2] 82 44 [2] 8d 5e [2] 93 43 [2] 91 42 [2] 8a 44 [2] 96 43 [2] 8a 6c }

  condition:
    any of them
}