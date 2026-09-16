rule TTP_XOR_QUAD_CurrentVersionRun_2efc {
  strings:
    $key_2efc = { 7d 93 [2] 59 9d [2] 72 b1 [2] 5c 93 [2] 48 88 [2] 47 92 [2] 59 8f [2] 5b 8e [2] 40 88 [2] 5c 8f [2] 40 a0 }

  condition:
    any of them
}