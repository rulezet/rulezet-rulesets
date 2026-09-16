rule TTP_XOR_WriteProcessMemory_8409 {
  strings:
    $key_8409 = { d3 7b [2] e1 59 [2] e7 6c [2] c9 6c [2] f6 70 }

  condition:
    any of them
}