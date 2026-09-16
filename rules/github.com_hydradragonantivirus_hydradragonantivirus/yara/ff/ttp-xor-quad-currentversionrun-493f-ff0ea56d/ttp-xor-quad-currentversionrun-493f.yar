rule TTP_XOR_QUAD_CurrentVersionRun_493f {
  strings:
    $key_493f = { 1a 50 [2] 3e 5e [2] 15 72 [2] 3b 50 [2] 2f 4b [2] 20 51 [2] 3e 4c [2] 3c 4d [2] 27 4b [2] 3b 4c [2] 27 63 }

  condition:
    any of them
}