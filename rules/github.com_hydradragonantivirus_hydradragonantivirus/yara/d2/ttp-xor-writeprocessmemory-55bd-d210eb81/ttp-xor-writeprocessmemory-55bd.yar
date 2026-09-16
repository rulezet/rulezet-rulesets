rule TTP_XOR_WriteProcessMemory_55bd {
  strings:
    $key_55bd = { 02 cf [2] 30 ed [2] 36 d8 [2] 18 d8 [2] 27 c4 }

  condition:
    any of them
}