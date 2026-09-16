rule TTP_XOR_WriteProcessMemory_385a {
  strings:
    $key_385a = { 6f 28 [2] 5d 0a [2] 5b 3f [2] 75 3f [2] 4a 23 }

  condition:
    any of them
}