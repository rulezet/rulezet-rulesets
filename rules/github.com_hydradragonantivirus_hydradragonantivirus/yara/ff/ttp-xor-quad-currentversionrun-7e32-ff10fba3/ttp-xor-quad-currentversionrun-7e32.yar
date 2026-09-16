rule TTP_XOR_QUAD_CurrentVersionRun_7e32 {
  strings:
    $key_7e32 = { 2d 5d [2] 09 53 [2] 22 7f [2] 0c 5d [2] 18 46 [2] 17 5c [2] 09 41 [2] 0b 40 [2] 10 46 [2] 0c 41 [2] 10 6e }

  condition:
    any of them
}