rule TTP_XOR_WriteProcessMemory_54bd {
  strings:
    $key_54bd = { 03 cf [2] 31 ed [2] 37 d8 [2] 19 d8 [2] 26 c4 }

  condition:
    any of them
}