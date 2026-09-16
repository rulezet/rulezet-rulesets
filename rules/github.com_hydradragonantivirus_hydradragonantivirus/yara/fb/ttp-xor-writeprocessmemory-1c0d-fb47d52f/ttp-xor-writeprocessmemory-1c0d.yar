rule TTP_XOR_WriteProcessMemory_1c0d {
  strings:
    $key_1c0d = { 4b 7f [2] 79 5d [2] 7f 68 [2] 51 68 [2] 6e 74 }

  condition:
    any of them
}