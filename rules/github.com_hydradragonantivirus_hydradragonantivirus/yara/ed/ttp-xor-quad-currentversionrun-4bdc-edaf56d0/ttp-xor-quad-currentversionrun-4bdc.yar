rule TTP_XOR_QUAD_CurrentVersionRun_4bdc {
  strings:
    $key_4bdc = { 18 b3 [2] 3c bd [2] 17 91 [2] 39 b3 [2] 2d a8 [2] 22 b2 [2] 3c af [2] 3e ae [2] 25 a8 [2] 39 af [2] 25 80 }

  condition:
    any of them
}