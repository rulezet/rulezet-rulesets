rule TTP_XOR_WriteProcessMemory_8be5 {
  strings:
    $key_8be5 = { dc 97 [2] ee b5 [2] e8 80 [2] c6 80 [2] f9 9c }

  condition:
    any of them
}