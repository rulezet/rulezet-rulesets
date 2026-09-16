rule TTP_XOR_WriteProcessMemory_84fc {
  strings:
    $key_84fc = { d3 8e [2] e1 ac [2] e7 99 [2] c9 99 [2] f6 85 }

  condition:
    any of them
}