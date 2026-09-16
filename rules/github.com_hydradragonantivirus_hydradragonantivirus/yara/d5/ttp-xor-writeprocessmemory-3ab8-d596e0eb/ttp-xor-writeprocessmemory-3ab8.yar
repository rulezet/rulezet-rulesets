rule TTP_XOR_WriteProcessMemory_3ab8 {
  strings:
    $key_3ab8 = { 6d ca [2] 5f e8 [2] 59 dd [2] 77 dd [2] 48 c1 }

  condition:
    any of them
}