rule TTP_XOR_WriteProcessMemory_68bd {
  strings:
    $key_68bd = { 3f cf [2] 0d ed [2] 0b d8 [2] 25 d8 [2] 1a c4 }

  condition:
    any of them
}