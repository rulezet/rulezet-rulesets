rule TTP_XOR_QUAD_CurrentVersionRun_322c {
  strings:
    $key_322c = { 61 43 [2] 45 4d [2] 6e 61 [2] 40 43 [2] 54 58 [2] 5b 42 [2] 45 5f [2] 47 5e [2] 5c 58 [2] 40 5f [2] 5c 70 }

  condition:
    any of them
}