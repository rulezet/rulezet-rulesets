rule TTP_XOR_QUAD_CurrentVersionRun_cafb {
  strings:
    $key_cafb = { 99 94 [2] bd 9a [2] 96 b6 [2] b8 94 [2] ac 8f [2] a3 95 [2] bd 88 [2] bf 89 [2] a4 8f [2] b8 88 [2] a4 a7 }

  condition:
    any of them
}