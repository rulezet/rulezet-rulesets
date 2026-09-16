rule TTP_XOR_WriteProcessMemory_8fb9 {
  strings:
    $key_8fb9 = { d8 cb [2] ea e9 [2] ec dc [2] c2 dc [2] fd c0 }

  condition:
    any of them
}