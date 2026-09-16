rule TTP_XOR_WriteProcessMemory_19bd {
  strings:
    $key_19bd = { 4e cf [2] 7c ed [2] 7a d8 [2] 54 d8 [2] 6b c4 }

  condition:
    any of them
}