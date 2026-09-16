rule TTP_XOR_WriteProcessMemory_6ab8 {
  strings:
    $key_6ab8 = { 3d ca [2] 0f e8 [2] 09 dd [2] 27 dd [2] 18 c1 }

  condition:
    any of them
}