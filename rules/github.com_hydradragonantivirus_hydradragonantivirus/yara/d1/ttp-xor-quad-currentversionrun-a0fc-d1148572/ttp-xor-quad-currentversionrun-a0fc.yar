rule TTP_XOR_QUAD_CurrentVersionRun_a0fc {
  strings:
    $key_a0fc = { f3 93 [2] d7 9d [2] fc b1 [2] d2 93 [2] c6 88 [2] c9 92 [2] d7 8f [2] d5 8e [2] ce 88 [2] d2 8f [2] ce a0 }

  condition:
    any of them
}