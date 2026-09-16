rule TTP_XOR_QUAD_CurrentVersionRun_ec0a {
  strings:
    $key_ec0a = { bf 65 [2] 9b 6b [2] b0 47 [2] 9e 65 [2] 8a 7e [2] 85 64 [2] 9b 79 [2] 99 78 [2] 82 7e [2] 9e 79 [2] 82 56 }

  condition:
    any of them
}