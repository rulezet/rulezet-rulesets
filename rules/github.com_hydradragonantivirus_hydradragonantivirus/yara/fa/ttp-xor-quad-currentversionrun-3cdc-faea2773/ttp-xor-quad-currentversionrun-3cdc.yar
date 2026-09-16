rule TTP_XOR_QUAD_CurrentVersionRun_3cdc {
  strings:
    $key_3cdc = { 6f b3 [2] 4b bd [2] 60 91 [2] 4e b3 [2] 5a a8 [2] 55 b2 [2] 4b af [2] 49 ae [2] 52 a8 [2] 4e af [2] 52 80 }

  condition:
    any of them
}