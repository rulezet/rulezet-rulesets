rule TTP_XOR_QUAD_CurrentVersionRun_552f {
  strings:
    $key_552f = { 06 40 [2] 22 4e [2] 09 62 [2] 27 40 [2] 33 5b [2] 3c 41 [2] 22 5c [2] 20 5d [2] 3b 5b [2] 27 5c [2] 3b 73 }

  condition:
    any of them
}