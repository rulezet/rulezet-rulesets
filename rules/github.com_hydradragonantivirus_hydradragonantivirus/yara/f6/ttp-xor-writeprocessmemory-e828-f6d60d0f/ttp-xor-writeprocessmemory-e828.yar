rule TTP_XOR_WriteProcessMemory_e828 {
  strings:
    $key_e828 = { bf 5a [2] 8d 78 [2] 8b 4d [2] a5 4d [2] 9a 51 }

  condition:
    any of them
}