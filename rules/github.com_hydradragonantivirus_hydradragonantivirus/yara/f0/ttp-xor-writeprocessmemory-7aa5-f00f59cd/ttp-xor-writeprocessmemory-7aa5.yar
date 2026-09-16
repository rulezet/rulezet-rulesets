rule TTP_XOR_WriteProcessMemory_7aa5 {
  strings:
    $key_7aa5 = { 2d d7 [2] 1f f5 [2] 19 c0 [2] 37 c0 [2] 08 dc }

  condition:
    any of them
}