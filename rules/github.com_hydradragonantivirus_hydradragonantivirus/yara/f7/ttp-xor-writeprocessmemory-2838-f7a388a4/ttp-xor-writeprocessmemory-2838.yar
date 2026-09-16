rule TTP_XOR_WriteProcessMemory_2838 {
  strings:
    $key_2838 = { 7f 4a [2] 4d 68 [2] 4b 5d [2] 65 5d [2] 5a 41 }

  condition:
    any of them
}