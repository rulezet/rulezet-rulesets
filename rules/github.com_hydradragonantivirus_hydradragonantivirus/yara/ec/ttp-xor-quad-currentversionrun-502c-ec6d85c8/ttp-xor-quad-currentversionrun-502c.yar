rule TTP_XOR_QUAD_CurrentVersionRun_502c {
  strings:
    $key_502c = { 03 43 [2] 27 4d [2] 0c 61 [2] 22 43 [2] 36 58 [2] 39 42 [2] 27 5f [2] 25 5e [2] 3e 58 [2] 22 5f [2] 3e 70 }

  condition:
    any of them
}