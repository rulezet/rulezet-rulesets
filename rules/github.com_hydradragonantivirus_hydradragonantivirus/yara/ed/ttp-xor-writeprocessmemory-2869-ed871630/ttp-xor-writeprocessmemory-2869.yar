rule TTP_XOR_WriteProcessMemory_2869 {
  strings:
    $key_2869 = { 7f 1b [2] 4d 39 [2] 4b 0c [2] 65 0c [2] 5a 10 }

  condition:
    any of them
}