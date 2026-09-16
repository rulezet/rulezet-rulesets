rule TTP_XOR_QUAD_CurrentVersionRun_ebdc {
  strings:
    $key_ebdc = { b8 b3 [2] 9c bd [2] b7 91 [2] 99 b3 [2] 8d a8 [2] 82 b2 [2] 9c af [2] 9e ae [2] 85 a8 [2] 99 af [2] 85 80 }

  condition:
    any of them
}