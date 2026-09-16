rule TTP_XOR_QUAD_CurrentVersionRun_351c {
  strings:
    $key_351c = { 66 73 [2] 42 7d [2] 69 51 [2] 47 73 [2] 53 68 [2] 5c 72 [2] 42 6f [2] 40 6e [2] 5b 68 [2] 47 6f [2] 5b 40 }

  condition:
    any of them
}