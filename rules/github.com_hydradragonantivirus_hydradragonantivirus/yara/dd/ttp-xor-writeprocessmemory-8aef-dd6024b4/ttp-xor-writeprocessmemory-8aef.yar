rule TTP_XOR_WriteProcessMemory_8aef {
  strings:
    $key_8aef = { dd 9d [2] ef bf [2] e9 8a [2] c7 8a [2] f8 96 }

  condition:
    any of them
}