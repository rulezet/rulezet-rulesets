rule TTP_XOR_QUAD_CurrentVersionRun_5732 {
  strings:
    $key_5732 = { 04 5d [2] 20 53 [2] 0b 7f [2] 25 5d [2] 31 46 [2] 3e 5c [2] 20 41 [2] 22 40 [2] 39 46 [2] 25 41 [2] 39 6e }

  condition:
    any of them
}