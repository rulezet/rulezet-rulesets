rule TTP_XOR_QUAD_CurrentVersionRun_52ef {
  strings:
    $key_52ef = { 01 80 [2] 25 8e [2] 0e a2 [2] 20 80 [2] 34 9b [2] 3b 81 [2] 25 9c [2] 27 9d [2] 3c 9b [2] 20 9c [2] 3c b3 }

  condition:
    any of them
}