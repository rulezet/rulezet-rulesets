rule TTP_XOR_QUAD_CurrentVersionRun_bf3d {
  strings:
    $key_bf3d = { ec 52 [2] c8 5c [2] e3 70 [2] cd 52 [2] d9 49 [2] d6 53 [2] c8 4e [2] ca 4f [2] d1 49 [2] cd 4e [2] d1 61 }

  condition:
    any of them
}