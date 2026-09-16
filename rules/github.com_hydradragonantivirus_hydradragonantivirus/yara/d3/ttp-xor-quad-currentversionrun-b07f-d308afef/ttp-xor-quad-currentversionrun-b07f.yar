rule TTP_XOR_QUAD_CurrentVersionRun_b07f {
  strings:
    $key_b07f = { e3 10 [2] c7 1e [2] ec 32 [2] c2 10 [2] d6 0b [2] d9 11 [2] c7 0c [2] c5 0d [2] de 0b [2] c2 0c [2] de 23 }

  condition:
    any of them
}