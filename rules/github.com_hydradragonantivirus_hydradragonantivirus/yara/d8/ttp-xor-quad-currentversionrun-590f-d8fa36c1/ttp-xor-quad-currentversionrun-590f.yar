rule TTP_XOR_QUAD_CurrentVersionRun_590f {
  strings:
    $key_590f = { 0a 60 [2] 2e 6e [2] 05 42 [2] 2b 60 [2] 3f 7b [2] 30 61 [2] 2e 7c [2] 2c 7d [2] 37 7b [2] 2b 7c [2] 37 53 }

  condition:
    any of them
}