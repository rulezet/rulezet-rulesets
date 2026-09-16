rule TTP_XOR_QUAD_CurrentVersionRun_352c {
  strings:
    $key_352c = { 66 43 [2] 42 4d [2] 69 61 [2] 47 43 [2] 53 58 [2] 5c 42 [2] 42 5f [2] 40 5e [2] 5b 58 [2] 47 5f [2] 5b 70 }

  condition:
    any of them
}