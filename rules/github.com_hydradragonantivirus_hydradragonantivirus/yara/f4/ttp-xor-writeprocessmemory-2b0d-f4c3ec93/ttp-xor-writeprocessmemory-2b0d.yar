rule TTP_XOR_WriteProcessMemory_2b0d {
  strings:
    $key_2b0d = { 7c 7f [2] 4e 5d [2] 48 68 [2] 66 68 [2] 59 74 }

  condition:
    any of them
}