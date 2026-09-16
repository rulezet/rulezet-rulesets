rule TTP_XOR_QUAD_CurrentVersionRun_182c {
  strings:
    $key_182c = { 4b 43 [2] 6f 4d [2] 44 61 [2] 6a 43 [2] 7e 58 [2] 71 42 [2] 6f 5f [2] 6d 5e [2] 76 58 [2] 6a 5f [2] 76 70 }

  condition:
    any of them
}