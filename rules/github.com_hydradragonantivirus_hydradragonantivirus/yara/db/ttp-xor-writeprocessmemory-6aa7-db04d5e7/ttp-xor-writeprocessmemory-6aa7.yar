rule TTP_XOR_WriteProcessMemory_6aa7 {
  strings:
    $key_6aa7 = { 3d d5 [2] 0f f7 [2] 09 c2 [2] 27 c2 [2] 18 de }

  condition:
    any of them
}