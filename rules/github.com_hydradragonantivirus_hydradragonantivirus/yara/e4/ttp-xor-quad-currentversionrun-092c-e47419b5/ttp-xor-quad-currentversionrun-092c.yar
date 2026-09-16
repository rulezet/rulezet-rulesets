rule TTP_XOR_QUAD_CurrentVersionRun_092c {
  strings:
    $key_092c = { 5a 43 [2] 7e 4d [2] 55 61 [2] 7b 43 [2] 6f 58 [2] 60 42 [2] 7e 5f [2] 7c 5e [2] 67 58 [2] 7b 5f [2] 67 70 }

  condition:
    any of them
}