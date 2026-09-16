rule TTP_XOR_QUAD_CurrentVersionRun_6bdc {
  strings:
    $key_6bdc = { 38 b3 [2] 1c bd [2] 37 91 [2] 19 b3 [2] 0d a8 [2] 02 b2 [2] 1c af [2] 1e ae [2] 05 a8 [2] 19 af [2] 05 80 }

  condition:
    any of them
}