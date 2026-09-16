rule TTP_XOR_WriteProcessMemory_030d {
  strings:
    $key_030d = { 54 7f [2] 66 5d [2] 60 68 [2] 4e 68 [2] 71 74 }

  condition:
    any of them
}