rule TTP_XOR_WriteProcessMemory_020d {
  strings:
    $key_020d = { 55 7f [2] 67 5d [2] 61 68 [2] 4f 68 [2] 70 74 }

  condition:
    any of them
}