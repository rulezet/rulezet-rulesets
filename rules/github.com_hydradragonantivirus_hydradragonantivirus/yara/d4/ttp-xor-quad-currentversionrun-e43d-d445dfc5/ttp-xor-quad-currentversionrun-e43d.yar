rule TTP_XOR_QUAD_CurrentVersionRun_e43d {
  strings:
    $key_e43d = { b7 52 [2] 93 5c [2] b8 70 [2] 96 52 [2] 82 49 [2] 8d 53 [2] 93 4e [2] 91 4f [2] 8a 49 [2] 96 4e [2] 8a 61 }

  condition:
    any of them
}