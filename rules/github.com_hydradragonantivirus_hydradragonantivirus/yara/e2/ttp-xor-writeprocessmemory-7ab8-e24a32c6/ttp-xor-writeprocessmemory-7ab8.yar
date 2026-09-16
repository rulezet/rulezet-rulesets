rule TTP_XOR_WriteProcessMemory_7ab8 {
  strings:
    $key_7ab8 = { 2d ca [2] 1f e8 [2] 19 dd [2] 37 dd [2] 08 c1 }

  condition:
    any of them
}