rule TTP_XOR_QUAD_CurrentVersionRun_0bdc {
  strings:
    $key_0bdc = { 58 b3 [2] 7c bd [2] 57 91 [2] 79 b3 [2] 6d a8 [2] 62 b2 [2] 7c af [2] 7e ae [2] 65 a8 [2] 79 af [2] 65 80 }

  condition:
    any of them
}