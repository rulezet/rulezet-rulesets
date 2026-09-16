rule TTP_XOR_QUAD_CurrentVersionRun_592d {
  strings:
    $key_592d = { 0a 42 [2] 2e 4c [2] 05 60 [2] 2b 42 [2] 3f 59 [2] 30 43 [2] 2e 5e [2] 2c 5f [2] 37 59 [2] 2b 5e [2] 37 71 }

  condition:
    any of them
}