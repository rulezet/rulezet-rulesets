rule TTP_XOR_QUAD_CurrentVersionRun_475d {
  strings:
    $key_475d = { 14 32 [2] 30 3c [2] 1b 10 [2] 35 32 [2] 21 29 [2] 2e 33 [2] 30 2e [2] 32 2f [2] 29 29 [2] 35 2e [2] 29 01 }

  condition:
    any of them
}