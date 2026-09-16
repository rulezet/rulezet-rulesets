rule TTP_XOR_QUAD_CurrentVersionRun_322f {
  strings:
    $key_322f = { 61 40 [2] 45 4e [2] 6e 62 [2] 40 40 [2] 54 5b [2] 5b 41 [2] 45 5c [2] 47 5d [2] 5c 5b [2] 40 5c [2] 5c 73 }

  condition:
    any of them
}