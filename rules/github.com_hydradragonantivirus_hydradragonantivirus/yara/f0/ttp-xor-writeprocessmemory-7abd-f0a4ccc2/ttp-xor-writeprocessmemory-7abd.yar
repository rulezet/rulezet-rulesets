rule TTP_XOR_WriteProcessMemory_7abd {
  strings:
    $key_7abd = { 2d cf [2] 1f ed [2] 19 d8 [2] 37 d8 [2] 08 c4 }

  condition:
    any of them
}