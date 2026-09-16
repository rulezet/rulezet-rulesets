rule TTP_XOR_WriteProcessMemory_060d {
  strings:
    $key_060d = { 51 7f [2] 63 5d [2] 65 68 [2] 4b 68 [2] 74 74 }

  condition:
    any of them
}