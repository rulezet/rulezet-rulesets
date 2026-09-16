rule TTP_XOR_WriteProcessMemory_b8cf {
  strings:
    $key_b8cf = { ef bd [2] dd 9f [2] db aa [2] f5 aa [2] ca b6 }

  condition:
    any of them
}