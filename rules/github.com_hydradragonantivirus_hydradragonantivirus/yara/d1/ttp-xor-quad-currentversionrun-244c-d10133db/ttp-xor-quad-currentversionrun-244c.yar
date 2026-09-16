rule TTP_XOR_QUAD_CurrentVersionRun_244c {
  strings:
    $key_244c = { 77 23 [2] 53 2d [2] 78 01 [2] 56 23 [2] 42 38 [2] 4d 22 [2] 53 3f [2] 51 3e [2] 4a 38 [2] 56 3f [2] 4a 10 }

  condition:
    any of them
}