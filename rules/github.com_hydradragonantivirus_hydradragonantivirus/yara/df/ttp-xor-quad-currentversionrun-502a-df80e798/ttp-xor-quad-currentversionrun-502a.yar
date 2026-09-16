rule TTP_XOR_QUAD_CurrentVersionRun_502a {
  strings:
    $key_502a = { 03 45 [2] 27 4b [2] 0c 67 [2] 22 45 [2] 36 5e [2] 39 44 [2] 27 59 [2] 25 58 [2] 3e 5e [2] 22 59 [2] 3e 76 }

  condition:
    any of them
}