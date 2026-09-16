rule TTP_XOR_WriteProcessMemory_2818 {
  strings:
    $key_2818 = { 7f 6a [2] 4d 48 [2] 4b 7d [2] 65 7d [2] 5a 61 }

  condition:
    any of them
}