rule TTP_XOR_WriteProcessMemory_8a9a {
  strings:
    $key_8a9a = { dd e8 [2] ef ca [2] e9 ff [2] c7 ff [2] f8 e3 }

  condition:
    any of them
}