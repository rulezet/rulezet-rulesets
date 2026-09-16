rule TTP_XOR_WriteProcessMemory_c8bd {
  strings:
    $key_c8bd = { 9f cf [2] ad ed [2] ab d8 [2] 85 d8 [2] ba c4 }

  condition:
    any of them
}