rule TTP_XOR_QUAD_CurrentVersionRun_0946 {
  strings:
    $key_0946 = { 5a 29 [2] 7e 27 [2] 55 0b [2] 7b 29 [2] 6f 32 [2] 60 28 [2] 7e 35 [2] 7c 34 [2] 67 32 [2] 7b 35 [2] 67 1a }

  condition:
    any of them
}