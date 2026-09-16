rule TTP_XOR_QUAD_CurrentVersionRun_2e62 {
  strings:
    $key_2e62 = { 7d 0d [2] 59 03 [2] 72 2f [2] 5c 0d [2] 48 16 [2] 47 0c [2] 59 11 [2] 5b 10 [2] 40 16 [2] 5c 11 [2] 40 3e }

  condition:
    any of them
}