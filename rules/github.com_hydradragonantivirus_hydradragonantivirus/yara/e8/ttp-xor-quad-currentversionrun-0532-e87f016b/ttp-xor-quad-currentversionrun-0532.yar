rule TTP_XOR_QUAD_CurrentVersionRun_0532 {
  strings:
    $key_0532 = { 56 5d [2] 72 53 [2] 59 7f [2] 77 5d [2] 63 46 [2] 6c 5c [2] 72 41 [2] 70 40 [2] 6b 46 [2] 77 41 [2] 6b 6e }

  condition:
    any of them
}