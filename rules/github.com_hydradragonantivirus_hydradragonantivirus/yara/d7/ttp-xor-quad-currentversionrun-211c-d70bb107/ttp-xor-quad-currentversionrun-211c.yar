rule TTP_XOR_QUAD_CurrentVersionRun_211c {
  strings:
    $key_211c = { 72 73 [2] 56 7d [2] 7d 51 [2] 53 73 [2] 47 68 [2] 48 72 [2] 56 6f [2] 54 6e [2] 4f 68 [2] 53 6f [2] 4f 40 }

  condition:
    any of them
}