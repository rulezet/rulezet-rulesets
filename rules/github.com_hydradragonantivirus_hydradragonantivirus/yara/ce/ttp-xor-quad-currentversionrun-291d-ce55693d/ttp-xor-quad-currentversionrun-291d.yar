rule TTP_XOR_QUAD_CurrentVersionRun_291d {
  strings:
    $key_291d = { 7a 72 [2] 5e 7c [2] 75 50 [2] 5b 72 [2] 4f 69 [2] 40 73 [2] 5e 6e [2] 5c 6f [2] 47 69 [2] 5b 6e [2] 47 41 }

  condition:
    any of them
}