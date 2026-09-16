rule TTP_XOR_WriteProcessMemory_2bec {
  strings:
    $key_2bec = { 7c 9e [2] 4e bc [2] 48 89 [2] 66 89 [2] 59 95 }

  condition:
    any of them
}