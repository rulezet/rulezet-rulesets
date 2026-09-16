rule TTP_XOR_QUAD_CurrentVersionRun_0afb {
  strings:
    $key_0afb = { 59 94 [2] 7d 9a [2] 56 b6 [2] 78 94 [2] 6c 8f [2] 63 95 [2] 7d 88 [2] 7f 89 [2] 64 8f [2] 78 88 [2] 64 a7 }

  condition:
    any of them
}