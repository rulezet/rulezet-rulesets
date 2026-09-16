rule TTP_XOR_QUAD_CurrentVersionRun_463c {
  strings:
    $key_463c = { 15 53 [2] 31 5d [2] 1a 71 [2] 34 53 [2] 20 48 [2] 2f 52 [2] 31 4f [2] 33 4e [2] 28 48 [2] 34 4f [2] 28 60 }

  condition:
    any of them
}