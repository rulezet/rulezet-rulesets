rule TTP_XOR_QUAD_CurrentVersionRun_ec3c {
  strings:
    $key_ec3c = { bf 53 [2] 9b 5d [2] b0 71 [2] 9e 53 [2] 8a 48 [2] 85 52 [2] 9b 4f [2] 99 4e [2] 82 48 [2] 9e 4f [2] 82 60 }

  condition:
    any of them
}