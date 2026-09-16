rule TTP_XOR_WriteProcessMemory_68ac {
  strings:
    $key_68ac = { 3f de [2] 0d fc [2] 0b c9 [2] 25 c9 [2] 1a d5 }

  condition:
    any of them
}