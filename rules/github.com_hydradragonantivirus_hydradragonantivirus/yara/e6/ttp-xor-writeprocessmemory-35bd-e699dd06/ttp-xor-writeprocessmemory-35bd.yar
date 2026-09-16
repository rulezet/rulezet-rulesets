rule TTP_XOR_WriteProcessMemory_35bd {
  strings:
    $key_35bd = { 62 cf [2] 50 ed [2] 56 d8 [2] 78 d8 [2] 47 c4 }

  condition:
    any of them
}