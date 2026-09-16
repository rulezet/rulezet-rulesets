rule TTP_XOR_QUAD_CurrentVersionRun_0fdc {
  strings:
    $key_0fdc = { 5c b3 [2] 78 bd [2] 53 91 [2] 7d b3 [2] 69 a8 [2] 66 b2 [2] 78 af [2] 7a ae [2] 61 a8 [2] 7d af [2] 61 80 }

  condition:
    any of them
}