rule TTP_XOR_WriteProcessMemory_24bd {
  strings:
    $key_24bd = { 73 cf [2] 41 ed [2] 47 d8 [2] 69 d8 [2] 56 c4 }

  condition:
    any of them
}