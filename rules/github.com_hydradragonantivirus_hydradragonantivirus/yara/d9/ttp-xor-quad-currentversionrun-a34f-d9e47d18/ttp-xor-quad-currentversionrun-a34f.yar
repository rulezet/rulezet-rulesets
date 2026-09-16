rule TTP_XOR_QUAD_CurrentVersionRun_a34f {
  strings:
    $key_a34f = { f0 20 [2] d4 2e [2] ff 02 [2] d1 20 [2] c5 3b [2] ca 21 [2] d4 3c [2] d6 3d [2] cd 3b [2] d1 3c [2] cd 13 }

  condition:
    any of them
}