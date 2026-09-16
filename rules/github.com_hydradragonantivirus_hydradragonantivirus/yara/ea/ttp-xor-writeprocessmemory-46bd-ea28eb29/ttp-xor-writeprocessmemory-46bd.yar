rule TTP_XOR_WriteProcessMemory_46bd {
  strings:
    $key_46bd = { 11 cf [2] 23 ed [2] 25 d8 [2] 0b d8 [2] 34 c4 }

  condition:
    any of them
}