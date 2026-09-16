rule TTP_XOR_WriteProcessMemory_89a8 {
  strings:
    $key_89a8 = { de da [2] ec f8 [2] ea cd [2] c4 cd [2] fb d1 }

  condition:
    any of them
}