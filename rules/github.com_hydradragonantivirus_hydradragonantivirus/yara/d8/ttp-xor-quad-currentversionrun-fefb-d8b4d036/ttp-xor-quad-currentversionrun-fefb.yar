rule TTP_XOR_QUAD_CurrentVersionRun_fefb {
  strings:
    $key_fefb = { ad 94 [2] 89 9a [2] a2 b6 [2] 8c 94 [2] 98 8f [2] 97 95 [2] 89 88 [2] 8b 89 [2] 90 8f [2] 8c 88 [2] 90 a7 }

  condition:
    any of them
}