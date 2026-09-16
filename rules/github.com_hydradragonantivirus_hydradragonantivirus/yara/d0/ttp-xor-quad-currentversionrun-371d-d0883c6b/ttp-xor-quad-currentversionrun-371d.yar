rule TTP_XOR_QUAD_CurrentVersionRun_371d {
  strings:
    $key_371d = { 64 72 [2] 40 7c [2] 6b 50 [2] 45 72 [2] 51 69 [2] 5e 73 [2] 40 6e [2] 42 6f [2] 59 69 [2] 45 6e [2] 59 41 }

  condition:
    any of them
}