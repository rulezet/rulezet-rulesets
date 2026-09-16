rule TTP_XOR_QUAD_CurrentVersionRun_070d {
  strings:
    $key_070d = { 54 62 [2] 70 6c [2] 5b 40 [2] 75 62 [2] 61 79 [2] 6e 63 [2] 70 7e [2] 72 7f [2] 69 79 [2] 75 7e [2] 69 51 }

  condition:
    any of them
}