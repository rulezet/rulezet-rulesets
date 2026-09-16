rule TTP_XOR_QUAD_CurrentVersionRun_bf1c {
  strings:
    $key_bf1c = { ec 73 [2] c8 7d [2] e3 51 [2] cd 73 [2] d9 68 [2] d6 72 [2] c8 6f [2] ca 6e [2] d1 68 [2] cd 6f [2] d1 40 }

  condition:
    any of them
}