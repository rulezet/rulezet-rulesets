rule TTP_XOR_WriteProcessMemory_0abd {
  strings:
    $key_0abd = { 5d cf [2] 6f ed [2] 69 d8 [2] 47 d8 [2] 78 c4 }

  condition:
    any of them
}