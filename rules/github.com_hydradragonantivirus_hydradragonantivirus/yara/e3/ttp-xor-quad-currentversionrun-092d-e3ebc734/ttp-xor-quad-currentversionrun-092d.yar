rule TTP_XOR_QUAD_CurrentVersionRun_092d {
  strings:
    $key_092d = { 5a 42 [2] 7e 4c [2] 55 60 [2] 7b 42 [2] 6f 59 [2] 60 43 [2] 7e 5e [2] 7c 5f [2] 67 59 [2] 7b 5e [2] 67 71 }

  condition:
    any of them
}