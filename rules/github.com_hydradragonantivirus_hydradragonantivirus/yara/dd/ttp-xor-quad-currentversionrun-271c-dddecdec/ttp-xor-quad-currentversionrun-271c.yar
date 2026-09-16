rule TTP_XOR_QUAD_CurrentVersionRun_271c {
  strings:
    $key_271c = { 74 73 [2] 50 7d [2] 7b 51 [2] 55 73 [2] 41 68 [2] 4e 72 [2] 50 6f [2] 52 6e [2] 49 68 [2] 55 6f [2] 49 40 }

  condition:
    any of them
}