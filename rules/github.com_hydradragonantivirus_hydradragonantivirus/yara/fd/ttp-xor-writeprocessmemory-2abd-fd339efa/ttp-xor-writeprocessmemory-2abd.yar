rule TTP_XOR_WriteProcessMemory_2abd {
  strings:
    $key_2abd = { 7d cf [2] 4f ed [2] 49 d8 [2] 67 d8 [2] 58 c4 }

  condition:
    any of them
}