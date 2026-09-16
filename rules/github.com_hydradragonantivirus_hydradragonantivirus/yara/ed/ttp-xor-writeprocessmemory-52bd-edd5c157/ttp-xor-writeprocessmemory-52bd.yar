rule TTP_XOR_WriteProcessMemory_52bd {
  strings:
    $key_52bd = { 05 cf [2] 37 ed [2] 31 d8 [2] 1f d8 [2] 20 c4 }

  condition:
    any of them
}