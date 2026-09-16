rule TTP_XOR_QUAD_CurrentVersionRun_1efc {
  strings:
    $key_1efc = { 4d 93 [2] 69 9d [2] 42 b1 [2] 6c 93 [2] 78 88 [2] 77 92 [2] 69 8f [2] 6b 8e [2] 70 88 [2] 6c 8f [2] 70 a0 }

  condition:
    any of them
}