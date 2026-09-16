rule TTP_XOR_QUAD_CurrentVersionRun_6efb {
  strings:
    $key_6efb = { 3d 94 [2] 19 9a [2] 32 b6 [2] 1c 94 [2] 08 8f [2] 07 95 [2] 19 88 [2] 1b 89 [2] 00 8f [2] 1c 88 [2] 00 a7 }

  condition:
    any of them
}