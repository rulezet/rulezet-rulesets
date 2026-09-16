rule TTP_XOR_WriteProcessMemory_f979 {
  strings:
    $key_f979 = { ae 0b [2] 9c 29 [2] 9a 1c [2] b4 1c [2] 8b 00 }

  condition:
    any of them
}